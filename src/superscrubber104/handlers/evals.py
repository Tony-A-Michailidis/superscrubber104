"""Evaluation sets and results that cross with a model (see ``superscrubber104.evals``).

Statically, each is parsed and recorded; whether a set names a delivered model, and whether
reference results belong to the delivered set and model, is decided across the delivery by
``superscrubber104.checks.evals``. Running a set is ``superscrubber104 eval run``.
"""

import re

from superscrubber104 import __version__
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject, ToolRef
from superscrubber104.evals import EvalError, parse_eval_set, parse_results
from superscrubber104.handlers.common import TooLarge, name_of, read_bytes

TOOL = ToolRef("superscrubber104.eval", __version__)
_KIND = re.compile(rb"""(?m)^\s*["']?kind["']?\s*:\s*["']?(EvalSet|EvalResults)\b""")
_LIMIT = 64 << 20


class EvalHandler:
    name = "eval"
    version = "1"
    kinds = frozenset({"eval.set", "eval.results"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if not name_of(artifact.ref).lower().endswith((".yaml", ".yml", ".json")):
            return None
        match = _KIND.search(artifact.head(8192))
        if match is None:
            return None
        return Detection("eval.set" if match.group(1) == b"EvalSet" else "eval.results", 80)

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        detection = self.detect(artifact)
        assert detection is not None  # noqa: S101 - only called after detect()
        subject = Subject.of_artifact(artifact.ref)
        try:
            data = read_bytes(artifact, _LIMIT)
            if detection.kind == "eval.set":
                evalset = parse_eval_set(data)
            else:
                results = parse_results(data)
        except (EvalError, TooLarge) as exc:
            ctx.recorder.fail(
                "eval.set.malformed", subject, tool=TOOL, detail={"problem": str(exc)}
            )
            return Inspection(kind=detection.kind)
        ctx.recorder.passed("eval.set.malformed")
        if detection.kind == "eval.set":
            meta: dict[str, object] = {
                "name": evalset.name,
                "model": evalset.model,
                "cases": len(evalset.cases),
                "canaries": sum(c.canary for c in evalset.cases),
                "comparison": evalset.method,
                "threshold": evalset.threshold,
            }
            return Inspection(kind="eval.set", metadata={"evalSet": meta})
        set_info = results.get("set") if isinstance(results.get("set"), dict) else {}
        model = results.get("model") if isinstance(results.get("model"), dict) else {}
        runtime = results.get("runtime") if isinstance(results.get("runtime"), dict) else {}
        assert isinstance(set_info, dict) and isinstance(model, dict)  # noqa: S101
        assert isinstance(runtime, dict)  # noqa: S101
        cases = results.get("cases")
        meta = {
            "set": set_info.get("name"),
            "setSha256": set_info.get("sha256"),
            "model": model.get("path"),
            "modelDigest": model.get("unitDigest"),
            "runtime": runtime.get("name"),
            "side": results.get("side"),
            "cases": len(cases) if isinstance(cases, list) else 0,
        }
        return Inspection(kind="eval.results", metadata={"evalResults": meta})
