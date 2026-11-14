"""Evaluation sets and reference results, across the delivery.

* An evaluation set must name a model package that is in the delivery (``eval.model.missing``).
* Reference results must be for an evaluation set that is in the delivery, byte for byte
  (``eval.reference.mismatch``), and for the model that is in the delivery: the model's unit
  digest (every member file's role and sha256) must be the one the results were produced with.
  A different digest means the evaluated model is not the model that crossed, so
  ``eval.model.digest-mismatch`` is final.
"""

from collections.abc import Mapping, Sequence

from airlock import __version__
from airlock.core.interfaces import Context
from airlock.core.model import Artifact, Subject, ToolRef, Unit, UnitKind

TOOL = ToolRef("airlock.eval", __version__)


def _meta(artifact: Artifact, key: str) -> Mapping[str, object]:
    value = artifact.metadata.get(key)
    return value if isinstance(value, dict) else {}


def model_unit(reference: str, units: Sequence[Unit]) -> Unit | None:
    wanted = reference.lower().strip("/")
    for unit in units:
        if unit.kind is not UnitKind.MODEL_PACKAGE:
            continue
        root = unit.root.display.lower().strip("/")
        if wanted in (root, unit.name.lower()) or root.endswith(f"/{wanted}"):
            return unit
    return None


def check_evals(artifacts: Sequence[Artifact], units: Sequence[Unit], ctx: Context) -> None:
    recorder = ctx.recorder
    sets = {
        a.hashes.get("sha256"): a
        for a in artifacts
        if "eval.set" in a.kinds and _meta(a, "evalSet")  # a malformed set is reported already
    }
    for artifact in sets.values():
        reference = str(_meta(artifact, "evalSet").get("model") or "")
        if model_unit(reference, units) is None:
            recorder.fail(
                "eval.model.missing",
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                detail={"model": reference},
            )
        else:
            recorder.passed("eval.model.missing")
    for artifact in artifacts:
        if "eval.results" not in artifact.kinds:
            continue
        meta = _meta(artifact, "evalResults")
        subject = Subject.of_artifact(artifact.ref)
        evalset = sets.get(str(meta.get("setSha256")))
        if evalset is None:
            recorder.fail(
                "eval.reference.mismatch",
                subject,
                tool=TOOL,
                detail={"set": meta.get("set"), "setSha256": meta.get("setSha256")},
            )
            continue
        recorder.passed("eval.reference.mismatch")
        reference = str(_meta(evalset, "evalSet").get("model") or meta.get("model") or "")
        unit = model_unit(reference, units)
        if unit is None:
            continue  # eval.model.missing already says so
        if meta.get("modelDigest") != unit.digest:
            recorder.fail(
                "eval.model.digest-mismatch",
                subject,
                tool=TOOL,
                detail={
                    "model": unit.id,
                    "evaluated": meta.get("modelDigest"),
                    "delivered": unit.digest,
                },
            )
        else:
            recorder.passed("eval.model.digest-mismatch")
