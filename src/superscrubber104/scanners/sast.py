"""Static analysis of first-party code: Semgrep (many languages) and Bandit (Python).

What is scanned is the delivery's own code: source files, scripts, agent hooks and skills, MCP
servers and model custom code (``modeling_*.py``), as top-level files. Third-party code under
``site-packages``, ``node_modules`` and virtual environments is left out: it is covered by the
vulnerability scan, and static analysis of other people's libraries is noise. Source inside an
archive that is not a package or an image (a zipped project) is recorded as not assessed.

Semgrep is given only local rules, from the pinned rules directory, with metrics and the version
check off; it never fetches rules from a registry. Bandit uses its built-in tests.
"""

import json
import os
import re
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Analysis, Severity, Subject
from superscrubber104.core.policy import PluginPolicy
from superscrubber104.scanners.base import DataInfo, Ready, ScanError, Target, files_under

_DEPENDENCY = re.compile(
    r"(^|/)(site-packages|dist-packages|node_modules|\.venv|venv|\.tox|__pycache__|\.git)(/|$)"
)
_PACKAGE_KINDS = ("python.wheel", "python.sdist", "npm.tarball", "container.image.archive")
_SOURCE_KINDS = ("source.", "executable.script", "agent.mcp-server", "agent.script")
_BATCH = 200  # files per run, which keeps command lines well inside Windows' limit
_LOWER = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


def _is_source(kinds: Sequence[str]) -> bool:
    return any(k.startswith(_SOURCE_KINDS) for k in kinds)


def source_targets(
    analysis: Analysis, targets: Sequence[Target], suffixes: tuple[str, ...] | None = None
) -> list[Target]:
    """First-party source among the top-level files."""
    by_path = {t.ref.path: t for t in targets}
    chosen = []
    for artifact in analysis.artifacts:
        if artifact.ref.member or not _is_source(artifact.kinds):
            continue
        if _DEPENDENCY.search(artifact.ref.path):
            continue
        if suffixes and not artifact.ref.path.lower().endswith(suffixes):
            continue
        if (target := by_path.get(artifact.ref.path)) is not None:
            chosen.append(target)
    return chosen


def has_source(analysis: Analysis) -> bool:
    return any(
        _is_source(a.kinds) and not _DEPENDENCY.search(a.ref.path) for a in analysis.artifacts
    )


def archived_source(analysis: Analysis) -> list[str]:
    """Top-level archives (not packages or images) that hold source code."""
    kinds = {a.ref.path: a.kinds for a in analysis.artifacts if not a.ref.member}
    holders = {
        a.ref.path
        for a in analysis.artifacts
        if a.ref.member and _is_source(a.kinds) and not _DEPENDENCY.search(a.ref.member[-1])
    }
    return sorted(
        p for p in holders if not any(k.startswith(_PACKAGE_KINDS) for k in kinds.get(p, ()))
    )


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _batches(items: Sequence[Target]) -> list[Sequence[Target]]:
    return [items[i : i + _BATCH] for i in range(0, len(items), _BATCH)]


class _Sast:
    """What Semgrep and Bandit share: targets, batching, mapping results back to artifacts."""

    name = ""
    capability = "sast"
    rules: tuple[str, ...] = ("sast.finding",)
    binary_names: tuple[str, ...] = ()
    suffixes: tuple[str, ...] | None = None

    def command(self, ready: Ready, files: Sequence[Target], output: Path) -> list[str]:
        raise NotImplementedError

    def results(self, report: dict[str, object], ready: Ready) -> list[dict[str, object]]:
        raise NotImplementedError

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        for path in archived_source(analysis):
            ctx.recorder.not_assessed(
                self.rules,
                Subject.of_path(path),
                tool=ready.tool,
                reason=f"source inside an archive is not scanned by {self.name}; deliver it "
                "unpacked",
            )
        chosen = source_targets(analysis, targets, self.suffixes)
        if not chosen:
            return
        flagged: set[str] = set()
        for batch in _batches(chosen):
            output = ready.workdir / f"{self.name}-{len(list(ready.workdir.glob('*.json')))}.json"
            ready.run(self.command(ready, batch, output), ok=(0, 1))
            try:
                report = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ScanError(f"unreadable {self.name} report: {exc}") from exc
            if not isinstance(report, dict):
                raise ScanError(f"{self.name} report is not a JSON object")
            by_key = {_key(str(t.location)): t for t in batch}
            for result in self.results(report, ready):
                target = by_key.get(_key(str(result["path"])))
                if target is None:
                    continue
                flagged.add(target.ref.path)
                if result.get("error"):
                    ctx.recorder.not_assessed(
                        self.rules,
                        Subject.of_artifact(target.ref),
                        tool=ready.tool,
                        reason=f"{self.name}: {result['error']}"[:300],
                    )
                    continue
                severity = result["severity"]
                assert isinstance(severity, Severity)  # noqa: S101
                ctx.recorder.fail(
                    "sast.finding",
                    Subject.of_artifact(target.ref, locator=f"line {result['line']}"),
                    tool=ready.tool,
                    detail={k: result.get(k) for k in ("rule", "message", "cwe", "confidence")},
                    attributes={
                        "scanner": self.name,
                        "ruleId": str(result["rule"]),
                        "category": str(result.get("category") or "unknown"),
                    },
                    severity=severity,
                    discriminator=f"{self.name}:{result['rule']}:{result['line']}",
                )
        ctx.recorder.passed("sast.finding", len({t.ref.path for t in chosen} - flagged))


def _rules_prefix(rules: Path | None) -> str:
    """The prefix Semgrep puts on the ids of rules loaded from ``rules``: its path, dotted.

    ``/home/user/tools/semgrep/rules/python/x.yaml`` gives ids such as
    ``home.user.tools.semgrep.rules.python.lang.x``. Left in, the evidence would carry the
    operator's directory, and the same rule would have another id on every host.
    """
    if rules is None:
        return ""
    parts = (p.strip("/\\:") for p in rules.parts)
    return ".".join(p for p in parts if p) + "."


def _strip(rule: str, prefix: str) -> str:
    return rule[len(prefix) :] if prefix and rule.startswith(prefix) else rule


class Semgrep(_Sast):
    name = "semgrep"
    binary_names: tuple[str, ...] = ("semgrep",)
    _SEVERITY: ClassVar[dict[str, Severity]] = {
        "CRITICAL": Severity.HIGH,
        "ERROR": Severity.HIGH,
        "HIGH": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "INFO": Severity.LOW,
        "LOW": Severity.LOW,
    }

    def version(self, ready: Ready) -> str | None:
        match = re.search(r"\d+\.\d+(?:\.\d+)?", ready.run(["--version"]).stdout)
        return match.group(0) if match else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        rules = policy.database
        if rules is None:
            return DataInfo(
                problem="plugins.semgrep.database (a local rules directory) is not set; "
                "superscrubber104 "
                "never lets Semgrep fetch rules from a registry"
            )
        files = files_under(rules, lambda p: p.suffix.lower() in (".yml", ".yaml"))
        if not files:
            return DataInfo(problem=f"no rule files (.yml, .yaml) in {rules}")
        return DataInfo(version=f"{len(files)} rule files", files=files)

    def command(self, ready: Ready, files: Sequence[Target], output: Path) -> list[str]:
        return [
            "scan",
            "--config",
            str(ready.policy.database),
            "--json",
            "--output",
            str(output),
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            *ready.policy.args,
            *(str(t.location) for t in files),
        ]

    def results(self, report: dict[str, object], ready: Ready) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        prefix = _rules_prefix(ready.policy.database)
        for item in _list(report.get("results")):
            if not isinstance(item, dict):
                continue
            extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            assert isinstance(extra, dict)  # noqa: S101
            meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            assert isinstance(meta, dict)  # noqa: S101
            start = item.get("start") if isinstance(item.get("start"), dict) else {}
            assert isinstance(start, dict)  # noqa: S101
            severity = self._SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
            if str(meta.get("confidence", "")).upper() == "LOW":
                severity = _LOWER[severity]
            cwe = meta.get("cwe")
            out.append(
                {
                    "path": item.get("path"),
                    "line": start.get("line"),
                    "rule": _strip(str(item.get("check_id") or ""), prefix),
                    "category": meta.get("category"),
                    "message": str(extra.get("message") or "")[:300],
                    "cwe": [str(c) for c in cwe][:5] if isinstance(cwe, list) else cwe,
                    "confidence": meta.get("confidence"),
                    "severity": severity,
                }
            )
        for error in _list(report.get("errors")):
            if isinstance(error, dict) and error.get("path"):
                message = error.get("message") or error.get("type") or "error"
                out.append({"path": error["path"], "error": str(message)[:200]})
        return out


class Bandit(_Sast):
    name = "bandit"
    binary_names: tuple[str, ...] = ("bandit",)
    suffixes: tuple[str, ...] | None = (".py", ".pyw")
    _SEVERITY: ClassVar[dict[str, Severity]] = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    def version(self, ready: Ready) -> str | None:
        match = re.search(r"bandit\s+v?(\d[\w.]*)", ready.run(["--version"]).stdout)
        return match.group(1) if match else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        return DataInfo()  # Bandit's tests are part of the program

    def command(self, ready: Ready, files: Sequence[Target], output: Path) -> list[str]:
        return [
            "-f",
            "json",
            "-q",
            "-o",
            str(output),
            *ready.policy.args,
            *(str(t.location) for t in files),
        ]

    def results(self, report: dict[str, object], ready: Ready) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        for item in _list(report.get("results")):
            if not isinstance(item, dict):
                continue
            severity = self._SEVERITY.get(str(item.get("issue_severity", "")).upper(), Severity.LOW)
            if str(item.get("issue_confidence", "")).upper() == "LOW":
                severity = _LOWER[severity]
            cwe = item.get("issue_cwe")
            out.append(
                {
                    "path": item.get("filename"),
                    "line": item.get("line_number"),
                    "rule": f"{item.get('test_id')} {item.get('test_name')}",
                    "message": str(item.get("issue_text") or "")[:300],
                    "cwe": f"CWE-{cwe.get('id')}" if isinstance(cwe, dict) else None,
                    "confidence": item.get("issue_confidence"),
                    "severity": severity,
                    "category": "security",  # every Bandit test is a security check
                }
            )
        for error in _list(report.get("errors")):
            if isinstance(error, dict) and error.get("filename"):
                out.append({"path": error["filename"], "error": str(error.get("reason"))[:200]})
        return out
