"""``superscrubber104 eval run``: run a pinned evaluation set through a pinned local runtime.

superscrubber104 never loads a model. The runtime is a program the site configures under
``runtimes`` in the policy (``llama-cli``, ``ollama run``, a script that calls a local server),
pinned and checked like a scanner, run with an argument list, a private working directory and the
network proxies closed. Each case's prompt goes into the runtime's arguments (``{prompt}``) or on
its standard input (``stdin: true``); its standard output is the answer.

The run records which set (by sha256), which model (by unit digest) and which runtime produced
each output. With ``--reference`` it compares against results from the other side: same set,
same model, and each output equal (``exact``) or similar enough (``similarity``).
"""

import hashlib
import json
import re
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from superscrubber104 import __version__
from superscrubber104.core.errors import ConfigError
from superscrubber104.core.model import (
    ArtifactRef,
    Assessment,
    PluginStatus,
    Stage,
    Subject,
    ToolRef,
    UnitKind,
)
from superscrubber104.core.policy import PluginPolicy, Policy
from superscrubber104.core.rules import Recorder
from superscrubber104.evals import (
    API_VERSION,
    EvalError,
    expectation,
    parse_eval_set,
    parse_results,
    similarity,
)
from superscrubber104.model_inspect import inspect_paths
from superscrubber104.scanners.base import DataInfo, Preflight, Ready, ScanError
from superscrubber104.session import Session, utc_now

TOOL = ToolRef("superscrubber104.eval", __version__)
_RULES = ("eval.case.failed", "eval.canary.failed", "eval.output.diverged")


class CommandRuntime:
    """A model runtime configured in the policy: run once per case, prompt in, answer out."""

    capability = "runtime"
    rules: tuple[str, ...] = ()

    def __init__(self, name: str) -> None:
        self.name = name
        self.binary_names: tuple[str, ...] = (name,)

    def version(self, ready: Ready) -> str | None:
        if not ready.policy.version_args:
            return None
        match = re.search(r"\d+(?:\.\d+)+", ready.run(list(ready.policy.version_args)).stdout)
        return match.group(0) if match else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        return DataInfo()

    def scan(self, *args: object) -> None:  # pragma: no cover - runtimes do not scan
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class EvalRun:
    assessment: Assessment
    results: dict[str, object]


def _arguments(template: Sequence[str], values: dict[str, str], prompt: str | None) -> list[str]:
    out = []
    for arg in template:
        for key, value in values.items():
            arg = arg.replace("{" + key + "}", value)
        if prompt is not None:
            arg = arg.replace("{prompt}", prompt)  # last, so a prompt's braces stay literal
        out.append(arg)
    return out


def run_eval(
    set_path: Path,
    model_path: Path,
    runtime: str,
    policy: Policy,
    *,
    reference: Path | None = None,
    side: str = "low",
    now: datetime | None = None,
) -> EvalRun:
    now = now or utc_now()
    try:
        evalset = parse_eval_set(set_path.read_bytes())
        ref_doc = parse_results(reference.read_bytes()) if reference else None
    except EvalError as exc:
        raise ConfigError(str(exc)) from exc
    runtime_policy = policy.runtimes.get(runtime)
    if runtime_policy is None:
        raise ConfigError(f"the policy configures no runtime named {runtime!r} (runtimes:)")
    packages = [
        u
        for u in inspect_paths(
            [model_path], policy=policy, run_plugins=False, now=now
        ).analysis.units
        if u.kind is UnitKind.MODEL_PACKAGE
    ]
    if len(packages) != 1:
        raise ConfigError(f"{model_path} is not one model package ({len(packages)} found)")
    unit_digest = packages[0].digest

    session = Session.start(policy, now)
    recorder = session.ctx.recorder
    set_ref = ArtifactRef(set_path.name)
    outputs: dict[str, str] = {}
    cases: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="superscrubber104-eval-") as scratch:
        status, ready = Preflight(
            CommandRuntime(runtime), runtime_policy, session.ctx, Path(scratch)
        ).run()
        if ready is None:
            recorder.not_assessed(
                _RULES,
                Subject.of_artifact(set_ref),
                tool=TOOL,
                reason=status.reason or "runtime unusable",
            )
        else:
            values = {
                "model": str(model_path.resolve()),
                "seed": evalset.settings.get("seed", "0"),
                "temperature": evalset.settings.get("temperature", "0"),
                "max_tokens": evalset.settings.get("maxTokens", "256"),
            }
            for case in evalset.cases:
                subject = Subject.of_artifact(set_ref, locator=f"case {case.id}")
                stdin = case.prompt.encode() if runtime_policy.stdin else None
                prompt = None if runtime_policy.stdin else case.prompt
                try:
                    completed = ready.run(
                        _arguments(runtime_policy.args, values, prompt), stdin=stdin
                    )
                except ScanError as exc:
                    recorder.error("eval.runtime.error", subject, tool=TOOL, error=str(exc))
                    continue
                output = completed.stdout.strip()
                outputs[case.id] = output
                passed, failed_check = expectation(case, output)
                rule = "eval.canary.failed" if case.canary else "eval.case.failed"
                if passed is False:
                    recorder.fail(
                        rule,
                        subject,
                        tool=TOOL,
                        detail={"check": failed_check, "output": output[:500]},
                        discriminator=case.id,
                    )
                elif passed:
                    recorder.passed(rule)
                cases.append(
                    {
                        "id": case.id,
                        "canary": case.canary,
                        "output": output,
                        "outputSha256": _sha(output),
                        "expectation": {True: "pass", False: "fail", None: "none"}[passed],
                    }
                )
    if ref_doc is not None:
        _compare(
            ref_doc,
            set_sha=evalset.sha256,
            unit_digest=unit_digest,
            outputs=outputs,
            method=evalset.method,
            threshold=evalset.threshold,
            set_ref=set_ref,
            recorder=recorder,
        )
    results: dict[str, object] = {
        "apiVersion": API_VERSION,
        "kind": "EvalResults",
        "side": side,
        "createdAt": now.isoformat(),
        "set": {"name": evalset.name, "sha256": evalset.sha256, "comparison": evalset.method},
        "model": {"path": evalset.model, "unitDigest": unit_digest},
        "runtime": _runtime(status),
        "settings": evalset.settings,
        "cases": cases,
    }
    assessment = session.finish(
        Stage.EVAL, manifest_digest=None, content_hashes={}, plugins=(status,)
    )
    return EvalRun(assessment, results)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _runtime(status: PluginStatus) -> dict[str, object]:
    return {"name": status.name, "version": status.version, "binarySha256": status.binary_sha256}


def _compare(
    reference: dict[str, object],
    *,
    set_sha: str,
    unit_digest: str,
    outputs: dict[str, str],
    method: str,
    threshold: int,
    set_ref: ArtifactRef,
    recorder: Recorder,
) -> None:
    ref_set = reference.get("set") if isinstance(reference.get("set"), dict) else {}
    ref_model = reference.get("model") if isinstance(reference.get("model"), dict) else {}
    assert isinstance(ref_set, dict) and isinstance(ref_model, dict)  # noqa: S101
    subject = Subject.of_artifact(set_ref)
    if ref_set.get("sha256") != set_sha:
        recorder.fail(
            "eval.reference.mismatch",
            subject,
            tool=TOOL,
            detail={"reference": ref_set.get("sha256"), "set": set_sha},
        )
        return
    recorder.passed("eval.reference.mismatch")
    if ref_model.get("unitDigest") != unit_digest:
        recorder.fail(
            "eval.model.digest-mismatch",
            subject,
            tool=TOOL,
            detail={"evaluated": ref_model.get("unitDigest"), "delivered": unit_digest},
        )
        return
    recorder.passed("eval.model.digest-mismatch")
    ref_cases = reference.get("cases")
    previous = {
        str(c.get("id")): str(c.get("output", ""))
        for c in (ref_cases if isinstance(ref_cases, list) else [])
        if isinstance(c, dict)
    }
    for case_id, output in sorted(outputs.items()):
        if case_id not in previous:
            continue
        score = similarity(previous[case_id], output)
        same = output == previous[case_id] if method == "exact" else score >= threshold
        if same:
            recorder.passed("eval.output.diverged")
            continue
        recorder.fail(
            "eval.output.diverged",
            Subject.of_artifact(set_ref, locator=f"case {case_id}"),
            tool=TOOL,
            detail={
                "method": method,
                "similarity": score,
                "threshold": threshold if method == "similarity" else 100,
                "reference": previous[case_id][:500],
                "output": output[:500],
            },
            discriminator=case_id,
        )


def write_results(path: Path, results: dict[str, object]) -> None:
    path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
