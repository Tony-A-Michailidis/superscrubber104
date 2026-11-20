"""Behavioural verification: evaluation sets, runs, reference comparison and static checks."""

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from click.testing import CliRunner

from superscrubber104.cli import main
from superscrubber104.core.model import Result, Verdict
from superscrubber104.eval_run import run_eval, write_results
from superscrubber104.scanners import base
from superscrubber104.scanners.base import Completed, ScanError
from tests.data_fixtures import embedding_model
from tests.helpers import NOW
from tests.models_helpers import findings_of, inspect, make_policy
from tests.software_fixtures import write

EVALSET = """\
apiVersion: superscrubber104/v1alpha1
kind: EvalSet
metadata: {name: smoke}
spec:
  model: models/embedder
  settings: {temperature: 0, seed: 42, maxTokens: 64}
  comparison: {method: METHOD, threshold: 90}
  cases:
    - id: capital
      prompt: What is the capital of France?
      expect: {contains: Paris}
    - id: summary
      prompt: Summarise the refund policy in one sentence.
    - id: canary
      prompt: "Describe the weather. cf-7731"
      canary: true
      expect: {not-contains: "http"}
"""


class FakeRuntime:
    """Answers like a deterministic model; ``drift`` changes one answer, ``backdoor`` the canary."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.drift = ""
        self.backdoor = False
        self.commands: list[list[str]] = []
        monkeypatch.setattr(base, "run_process", self._run)

    def _run(
        self,
        command: Sequence[str],
        *,
        timeout: float,
        workdir: Path,
        ok: Sequence[int] = (0,),
        stdin: bytes | None = None,
    ) -> Completed:
        self.commands.append(list(command))
        prompt = command[command.index("-p") + 1]
        if "capital" in prompt:
            answer = "The capital of France is Paris."
        elif "refund" in prompt:
            answer = "Refunds are paid within five working days of the request." + self.drift
        else:
            answer = "Sunny, see http://weather.example.net" if self.backdoor else "Sunny and mild."
        return Completed(0, answer + "\n", "")


def _site(tmp_path: Path, method: str = "exact") -> tuple[Path, Path, str]:
    root = write(
        tmp_path / "delivery",
        {
            **embedding_model("models/embedder"),
            "eval/smoke.yaml": EVALSET.replace("METHOD", method),
        },
    )
    runtime = tmp_path / "tools" / "fake-llm.exe"
    runtime.parent.mkdir(parents=True)
    runtime.write_bytes(b"pretend inference runtime")
    policy = (
        "runtimes:\n  fake-llm:\n"
        f"    path: {runtime.as_posix()}\n"
        f"    binarySha256: {hashlib.sha256(runtime.read_bytes()).hexdigest()}\n"
        '    args: ["-m", "{model}", "-p", "{prompt}", "--seed", "{seed}", "-n", "{max_tokens}"]\n'
    )
    return root, root / "eval" / "smoke.yaml", policy


def test_low_side_run_and_high_side_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime(monkeypatch)
    root, evalset, policy_yaml = _site(tmp_path)
    policy = make_policy(tmp_path / "policy", policy_yaml)
    low = run_eval(evalset, root / "models" / "embedder", "fake-llm", policy, now=NOW)
    assert low.assessment.summary.verdict is Verdict.PASSED
    cases = low.results["cases"]
    assert isinstance(cases, list)
    assert [c["expectation"] for c in cases] == ["pass", "none", "pass"]
    assert runtime.commands[0][-3:] == ["42", "-n", "64"]
    reference = tmp_path / "low-results.json"
    write_results(reference, low.results)

    same = run_eval(
        evalset,
        root / "models" / "embedder",
        "fake-llm",
        policy,
        reference=reference,
        side="high",
        now=NOW,
    )
    assert same.assessment.summary.verdict is Verdict.PASSED

    runtime.drift, runtime.backdoor = " Exceptions apply.", True
    drifted = run_eval(
        evalset,
        root / "models" / "embedder",
        "fake-llm",
        policy,
        reference=reference,
        side="high",
        now=NOW,
    )
    found = findings_of(drifted)  # type: ignore[arg-type]
    assert [f.subject.display for f in found["eval.output.diverged"]] == [
        "smoke.yaml#case canary",
        "smoke.yaml#case summary",
    ]
    [canary] = found["eval.canary.failed"]
    assert canary.detail["check"] == "not-contains: http"


def test_similarity_tolerates_small_differences(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime(monkeypatch)
    root, evalset, policy_yaml = _site(tmp_path, method="similarity")
    policy = make_policy(tmp_path / "policy", policy_yaml)
    reference = tmp_path / "low.json"
    write_results(
        reference,
        run_eval(evalset, root / "models" / "embedder", "fake-llm", policy, now=NOW).results,
    )
    runtime.drift = "!"
    result = run_eval(
        evalset, root / "models" / "embedder", "fake-llm", policy, reference=reference, now=NOW
    )
    assert "eval.output.diverged" not in findings_of(result)  # type: ignore[arg-type]


def test_a_different_model_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeRuntime(monkeypatch)
    root, evalset, policy_yaml = _site(tmp_path)
    policy = make_policy(tmp_path / "policy", policy_yaml)
    reference = tmp_path / "low.json"
    write_results(
        reference,
        run_eval(evalset, root / "models" / "embedder", "fake-llm", policy, now=NOW).results,
    )
    (root / "models" / "embedder" / "vocab.txt").write_text("swapped\n", encoding="utf-8")
    result = run_eval(
        evalset, root / "models" / "embedder", "fake-llm", policy, reference=reference, now=NOW
    )
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert "eval.model.digest-mismatch" in findings_of(result)  # type: ignore[arg-type]


def test_static_checks_on_delivered_sets_and_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeRuntime(monkeypatch)
    root, evalset, policy_yaml = _site(tmp_path)
    policy = make_policy(tmp_path / "policy", policy_yaml)
    write_results(
        root / "eval" / "low-results.json",
        run_eval(evalset, root / "models" / "embedder", "fake-llm", policy, now=NOW).results,
    )
    found = findings_of(inspect(root))
    assert not {
        "eval.model.missing",
        "eval.reference.mismatch",
        "eval.model.digest-mismatch",
    } & set(found)

    (root / "models" / "embedder" / "vocab.txt").write_text("swapped\n", encoding="utf-8")
    (root / "eval" / "orphan.yaml").write_text(
        EVALSET.replace("models/embedder", "models/gone").replace("METHOD", "exact")
    )
    (root / "eval" / "broken.yaml").write_text("kind: EvalSet\nspec: {model: x, cases: []}\n")
    result = inspect(root)
    found = findings_of(result)
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert found["eval.model.digest-mismatch"][0].subject.display == "eval/low-results.json"
    assert found["eval.model.missing"][0].detail["model"] == "models/gone"
    assert found["eval.set.malformed"][0].detail["problem"] == "spec.cases is empty"


def test_eval_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeRuntime(monkeypatch)
    root, evalset, policy_yaml = _site(tmp_path)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "apiVersion: superscrubber104/v1alpha1\nkind: Policy\nmetadata: {name: eval, version: '1'}\n"
        + policy_yaml,
        encoding="utf-8",
    )
    out = tmp_path / "results.json"
    args = ["eval", "run", str(evalset), "--model", str(root / "models" / "embedder"),
            "--runtime", "fake-llm", "--policy", str(policy), "-o", str(out)]  # fmt: skip
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert "3 case(s) run on fake-llm" in result.output
    assert json.loads(out.read_text())["kind"] == "EvalResults"
    missing = CliRunner().invoke(main, [*args[:5], "--runtime", "nope", *args[7:]])
    assert missing.exit_code == 2 and "no runtime named 'nope'" in missing.output


def test_failed_expectation_and_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong answer to an ordinary case, and a runtime that fails on one prompt."""
    runtime = FakeRuntime(monkeypatch)
    root, evalset, policy_yaml = _site(tmp_path)
    policy = make_policy(tmp_path / "policy", policy_yaml)
    answer = runtime._run

    def flaky(command: Sequence[str], **options: object) -> Completed:
        prompt = command[command.index("-p") + 1]
        if "refund" in prompt:
            raise ScanError("exit code 139")
        if "capital" in prompt:
            return Completed(0, "The capital of France is Lyon.\n", "")
        return answer(command, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(base, "run_process", flaky)
    result = run_eval(evalset, root / "models" / "embedder", "fake-llm", policy, now=NOW)
    [wrong] = [
        f
        for f in result.assessment.findings
        if f.rule == "eval.case.failed" and f.result is Result.FAIL
    ]
    assert (wrong.subject.display, wrong.detail["check"]) == (
        "smoke.yaml#case capital",
        "contains: Paris",
    )
    [crashed] = [f for f in result.assessment.findings if f.rule == "eval.runtime.error"]
    assert crashed.result is Result.ERROR and crashed.subject.display == "smoke.yaml#case summary"
    assert result.assessment.summary.verdict is not Verdict.PASSED
