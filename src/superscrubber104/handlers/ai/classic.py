"""Classic machine-learning models in their own formats, and MLflow model directories.

* **XGBoost** (JSON and UBJSON), **LightGBM** (text) and **CatBoost** (``.cbm``) store trees as
  data; they are recognised and form model packages like any other weights. Pickled scikit-learn,
  XGBoost or LightGBM models are pickles and get the pickle checks.
* **skops** (``.skops``) is a zip whose ``schema.json`` names every type it will instantiate. The
  types are classified like pickle imports: skops refuses untrusted types unless the loader lists
  them, and whatever is listed is constructed.
* **PMML** is XML and is recognised.
* **MLflow** (``MLmodel``): the flavours are recorded, and a ``python_function`` model that brings
  its own loader module, a pickled ``python_model`` or a ``code`` directory is flagged, because
  loading it runs that code. The environment files beside it (``requirements.txt``,
  ``conda.yaml``) are checked by the Python handlers.
"""

import json
import re
import zipfile
from collections.abc import Callable, Iterator

import yaml

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Severity, Subject
from superscrubber104.core.yamlio import load_untrusted_yaml
from superscrubber104.formats.pickle_scan import classify
from superscrubber104.handlers.ai.common import TOOL, claim, name_of
from superscrubber104.handlers.common import mapping, read_text

_XGB_JSON = re.compile(rb'^\s*\{\s*"learner"\s*:')
_SKOPS_SAFE = ("sklearn.", "numpy.", "scipy.", "builtins.")
Reader = Callable[[ArtifactView, Context], Inspection]


def _types(node: object, depth: int = 0) -> Iterator[str]:
    """``module.Class`` of every object in a skops schema."""
    if depth > 64:
        return
    if isinstance(node, dict):
        module, cls = node.get("__module__"), node.get("__class__")
        if isinstance(module, str) and isinstance(cls, str):
            yield f"{module}.{cls}"
        for value in node.values():
            yield from _types(value, depth + 1)
    elif isinstance(node, list):
        for value in node:
            yield from _types(value, depth + 1)


def _skops(view: ArtifactView, ctx: Context) -> Inspection:
    with view.open() as stream, zipfile.ZipFile(stream) as archive:
        info = archive.getinfo("schema.json")
        if info.file_size > 64 << 20:
            raise ValueError("schema.json is larger than superscrubber104 will read")
        schema = json.loads(archive.read(info))
    types = sorted(set(_types(schema)))
    allowed = ctx.policy.allowlists.get("pickle-globals")
    patterns = allowed.entries if allowed else ()
    flagged: dict[str, str] = {}
    for full in types:
        module, _, name = full.rpartition(".")
        verdict = classify(module, name, [str(p) for p in patterns])
        if verdict == "dangerous" or (verdict == "unknown" and not full.startswith(_SKOPS_SAFE)):
            flagged[full] = verdict
    if flagged:
        ctx.recorder.fail(
            "model.skops.untrusted-type",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"types": [{"type": t, "class": v} for t, v in sorted(flagged.items())]},
            severity=Severity.CRITICAL if "dangerous" in flagged.values() else Severity.HIGH,
        )
    else:
        ctx.recorder.passed("model.skops.untrusted-type")
    facts = {"format": "skops", "types": len(types)}
    return Inspection(
        kind="model.skops",
        metadata={"classicModel": {**facts, "typeNames": types[:200]}},
        claims=(claim(view, "classic-model", facts, root=view.ref),),
    )


def _simple(kind: str, fmt: str) -> Reader:
    def read(view: ArtifactView, ctx: Context) -> Inspection:
        facts = {"format": fmt}
        return Inspection(
            kind=kind,
            metadata={"classicModel": facts},
            claims=(claim(view, "classic-model", facts, root=view.ref),),
        )

    return read


def _mlflow(view: ArtifactView, ctx: Context) -> Inspection:
    try:
        data = mapping(load_untrusted_yaml(read_text(view, 1 << 20)))
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        ctx.recorder.not_assessed(
            ("model.mlflow.custom-code",),
            Subject.of_artifact(view.ref),
            tool=TOOL,
            reason=f"MLmodel is not valid YAML: {str(exc)[:200]}",
        )
        return Inspection(kind="model.mlflow", metadata={"classicModel": {"error": True}})
    flavors = mapping(data.get("flavors"))
    pyfunc = mapping(flavors.get("python_function"))
    reasons: list[str] = []
    loader = pyfunc.get("loader_module")
    if isinstance(loader, str) and not loader.startswith("mlflow."):
        reasons.append(f"loader module {loader}")
    if pyfunc.get("python_model") or pyfunc.get("cloudpickle_version"):
        reasons.append(f"pickled python_model {pyfunc.get('python_model') or ''}".strip())
    if pyfunc.get("code"):
        reasons.append(f"code directory {pyfunc.get('code')}")
    subject = Subject.of_artifact(view.ref)
    if reasons:
        ctx.recorder.fail(
            "model.mlflow.custom-code", subject, tool=TOOL, detail={"reasons": reasons}
        )
    else:
        ctx.recorder.passed("model.mlflow.custom-code")
    facts = {
        "format": "mlflow",
        "flavors": sorted(str(f) for f in flavors),
        "runId": data.get("run_id"),
        "modelUuid": data.get("model_uuid"),
        "created": str(data.get("utc_time_created")) if data.get("utc_time_created") else None,
        "mlflowVersion": data.get("mlflow_version"),
    }
    return Inspection(
        kind="model.mlflow",
        metadata={"mlflow": facts},
        claims=(claim(view, "mlflow-model", facts),),
    )


def _dispatch(view: ArtifactView) -> Reader | None:
    name = name_of(view.ref)
    lowered = name.lower()
    head = view.head(512)
    if name == "MLmodel" and b"flavors" in view.head(65536):
        return _mlflow
    if lowered.endswith(".json") and _XGB_JSON.match(head):
        return _simple("model.xgboost", "xgboost-json")
    if lowered.endswith(".ubj") and head[:1] == b"{" and b"learner" in head[:32]:
        return _simple("model.xgboost", "xgboost-ubjson")
    if head.startswith(b"tree\nversion=v"):
        return _simple("model.lightgbm", "lightgbm")
    if head.startswith(b"CBM1"):
        return _simple("model.catboost", "catboost")
    if lowered.endswith(".pmml") and b"<PMML" in head:
        return _simple("model.pmml", "pmml")
    if lowered.endswith(".skops") and head.startswith(b"PK\x03\x04"):
        return _skops
    return None


class ClassicModelHandler:
    name = "classic-model"
    version = "1"
    kinds = frozenset(
        {
            "model.xgboost",
            "model.lightgbm",
            "model.catboost",
            "model.pmml",
            "model.skops",
            "model.mlflow",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("model.classic", 70) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        reader = _dispatch(artifact)
        assert reader is not None  # noqa: S101 - only called after detect()
        return reader(artifact, ctx)
