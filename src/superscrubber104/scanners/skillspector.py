"""NVIDIA SkillSpector: a scanner for agent skills and MCP servers, wrapped as a pinned plugin.

SkillSpector (github.com/NVIDIA/SkillSpector, Apache-2.0) looks for prompt injection, data
exfiltration, credential access, excessive agency, tool poisoning and supply-chain risks in a
skill before it is installed. superscrubber104 runs it like any other scanner: pinned, after the
pre-flight, in the network-blocked sandbox, and records its issues as ``skill.finding``.

What is scanned, as directories: every agent skill (a folder with a ``SKILL.md``) and every MCP
server's package root (the nearest folder above the server code with a ``package.json`` or
``pyproject.toml``). Skills inside an archive are recorded as not assessed.

Three rules hold whatever the policy's ``args`` say:

* ``--no-llm`` always. Its default mode sends file contents to a hosted model; nothing leaves the
  enclave, so only its static analysis runs.
* The matched text (``finding``, ``code_snippet``) is never recorded: it can be the secret a rule
  found. A finding carries the rule id, category, pattern, line, confidence and explanation.
* What SkillSpector says it could not finish (its ``analysis_completeness`` ledger) is recorded as
  not assessed for that file. Its known-vulnerability lookup (SC4) needs OSV.dev, which the sandbox
  never reaches; it then uses a small built-in list, and the evidence says so. Trivy is the
  vulnerability scanner.
"""

import json
import posixpath
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import ClassVar

from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Analysis, ArtifactRef, Severity, Subject
from superscrubber104.core.policy import PluginPolicy
from superscrubber104.handlers.common import TEST_CONTEXT, TEST_PATH
from superscrubber104.scanners.base import DataInfo, Ready, ScanError, Target, files_under

_DEPENDENCY = re.compile(
    r"(^|/)(site-packages|dist-packages|node_modules|\.venv|venv|\.tox|__pycache__|\.git)(/|$)"
)
_PROJECT_FILES = ("package.json", "pyproject.toml")
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}
_LOWER = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}
_TEXT = 300  # explanation and remediation are kept, truncated; the matched text never is
# Issues that say an analysis was incomplete (AE1: "Incomplete referenced artifact analysis")
_INCOMPLETE = frozenset({"AE1"})


def _is_skill(kinds: Sequence[str]) -> bool:
    return "agent.skill" in kinds


def _is_server(kinds: Sequence[str]) -> bool:
    return "agent.mcp-server" in kinds


def has_skills(analysis: Analysis) -> bool:
    return any(
        (_is_skill(a.kinds) or _is_server(a.kinds)) and not _DEPENDENCY.search(a.ref.display)
        for a in analysis.artifacts
    )


def _parent(path: str) -> str:
    return posixpath.dirname(path) or "."


def _inside(path: str, directory: str) -> bool:
    return directory == "." or path == directory or path.startswith(directory + "/")


def skill_roots(analysis: Analysis) -> tuple[list[str], list[str]]:
    """(directories to scan, top-level archives that hold skills), delivery-relative."""
    top = [a for a in analysis.artifacts if not a.ref.member]
    paths = {a.ref.path for a in top}
    roots: set[str] = set()
    for artifact in top:
        if _DEPENDENCY.search(artifact.ref.path):
            continue
        if _is_skill(artifact.kinds):
            roots.add(_parent(artifact.ref.path))
        elif _is_server(artifact.kinds):
            directory = _parent(artifact.ref.path)
            found = directory
            while True:  # the server's package root, if it has one
                if any(f"{directory}/{name}" in paths for name in _PROJECT_FILES) or (
                    directory == "." and any(name in paths for name in _PROJECT_FILES)
                ):
                    found = directory
                    break
                if directory == ".":
                    break
                directory = _parent(directory)
            roots.add(found)
    # a folder inside another one being scanned is covered by it
    chosen = sorted(r for r in roots if not any(o != r and _inside(r, o) for o in roots))
    archived = sorted(
        {
            a.ref.path
            for a in analysis.artifacts
            if a.ref.member
            and (_is_skill(a.kinds) or _is_server(a.kinds))
            and not _DEPENDENCY.search(a.ref.display)
        }
    )
    return chosen, archived


def _on_disk(directory: str, targets: Sequence[Target]) -> Path | None:
    """Where the delivery directory ``directory`` is on disk, from any file under it."""
    for target in targets:
        if not _inside(target.ref.path, directory) or target.ref.path == directory:
            continue
        below = PurePosixPath(target.ref.path).relative_to("." if directory == "." else directory)
        location = target.location
        for _ in below.parts:
            location = location.parent
        return location
    return None


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


class SkillSpector:
    name = "skillspector"
    capability = "agent-skills"
    rules: tuple[str, ...] = ("skill.finding",)
    binary_names: tuple[str, ...] = ("skillspector",)
    _RULE_SUFFIXES: ClassVar[tuple[str, ...]] = (".yar", ".yara")

    def version(self, ready: Ready) -> str | None:
        match = re.search(r"\bv?(\d+\.\d+(?:\.\d+)?)", ready.run(["--version"]).stdout)
        return match.group(1) if match else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        """Its own YARA rules and patterns are part of the program. ``database``, if set, is a
        directory of site YARA rules, every one pinned (``--yara-rules-dir``)."""
        if policy.database is None:
            return DataInfo()
        files = files_under(policy.database, lambda p: p.suffix.lower() in self._RULE_SUFFIXES)
        if not files:
            return DataInfo(problem=f"no YARA rule files (.yar, .yara) in {policy.database}")
        return DataInfo(version=f"{len(files)} site YARA rule files", files=files)

    def command(self, ready: Ready, directory: Path) -> list[str]:
        extra = ["--yara-rules-dir", str(ready.policy.database)] if ready.policy.database else []
        # --no-llm last, after the policy's own arguments: nothing turns the model on
        return ["scan", str(directory), "--format", "json", *extra, *ready.policy.args, "--no-llm"]

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        roots, archived = skill_roots(analysis)
        for path in archived:
            ctx.recorder.not_assessed(
                self.rules,
                Subject.of_path(path),
                tool=ready.tool,
                reason="agent skills or MCP servers inside an archive are not scanned by "
                "SkillSpector; deliver them unpacked",
            )
        known = {a.ref.path for a in analysis.artifacts if not a.ref.member}
        failures = 0
        for root in roots:
            location = _on_disk(root, targets)
            subject = Subject.of_path(root)
            if location is None:
                continue
            try:
                completed = ready.run(self.command(ready, location), ok=(0, 1))
                report = json.loads(completed.stdout)
                if not isinstance(report, dict):
                    raise ScanError("the report is not a JSON object")
            except (ScanError, ValueError) as exc:
                failures += 1
                ctx.recorder.error(
                    "plugin.scan.error", subject, tool=ready.tool, error=f"{root}: {exc}"[:500]
                )
                ctx.recorder.not_assessed(
                    self.rules, subject, tool=ready.tool, reason="SkillSpector did not complete"
                )
                continue
            self._record(report, root, known, ctx, ready)
        if roots and failures == len(roots):
            raise ScanError("every SkillSpector run failed")

    def _record(
        self, report: dict[str, object], root: str, known: set[str], ctx: Context, ready: Ready
    ) -> None:
        recorder = ctx.recorder

        def where(file: object) -> str | None:
            name = _str(file)
            if name is None:
                return None
            path = posixpath.normpath(name if root == "." else f"{root}/{name}")
            return path if path in known else None

        flagged: set[str] = set()
        seen: Counter[str] = Counter()
        issues = report.get("issues")
        for issue in issues if isinstance(issues, list) else []:
            if not isinstance(issue, dict):
                continue
            location = issue.get("location") if isinstance(issue.get("location"), dict) else {}
            assert isinstance(location, dict)  # noqa: S101
            path = where(location.get("file"))
            line = (
                location.get("start_line") if isinstance(location.get("start_line"), int) else None
            )
            rule = _str(issue.get("id")) or "unknown"
            if rule in _INCOMPLETE:  # "not proof of malicious evasion", SkillSpector says: a gap
                recorder.not_assessed(
                    self.rules,
                    Subject.of_artifact(ArtifactRef(path)) if path else Subject.of_path(root),
                    tool=ready.tool,
                    reason="SkillSpector did not finish: "
                    + (_str(issue.get("explanation")) or "a referenced artifact")[:_TEXT],
                )
                continue
            severity = _SEVERITY.get(str(issue.get("severity", "")).upper(), Severity.MEDIUM)
            confidence = issue.get("confidence")
            if isinstance(confidence, int | float) and confidence < 0.5:
                severity = _LOWER[severity]
            # a server's or skill's own tests and examples: recorded, at low severity, as for
            # secrets and MCP server capabilities
            test_path = path is not None and bool(TEST_PATH.search(path))
            if test_path:
                severity = Severity.LOW
            if path is not None:
                flagged.add(path)
                subject = Subject.of_artifact(
                    ArtifactRef(path), locator=f"line {line}" if line else None
                )
            else:  # outside the delivery's files (a virtual member): the folder itself
                subject = Subject.of_path(root)
            key = f"{rule}:{path or root}:{line}"
            seen[key] += 1
            recorder.fail(
                "skill.finding",
                subject,
                tool=ready.tool,
                detail={
                    "rule": rule,
                    "category": _str(issue.get("category")),
                    "pattern": _str(issue.get("pattern")),
                    "explanation": (_str(issue.get("explanation")) or "")[:_TEXT] or None,
                    "remediation": (_str(issue.get("remediation")) or "")[:_TEXT] or None,
                    "confidence": str(confidence) if confidence is not None else None,
                    "scanned": root,
                    "context": TEST_CONTEXT if test_path else None,
                },
                attributes={
                    "scanner": self.name,
                    "ruleId": rule,
                    "category": _str(issue.get("category")) or "unknown",
                },
                severity=severity,
                discriminator=f"{key}:{seen[key]}",
            )
        completeness = report.get("analysis_completeness")
        exceptions = completeness.get("ledger_exceptions") if isinstance(completeness, dict) else []
        for entry in exceptions if isinstance(exceptions, list) else []:
            if not isinstance(entry, dict):
                continue
            path = where(entry.get("path"))
            analyzers = " ".join(str(a) for a in entry.get("analyzers") or [])
            if (
                "supply_chain_dependencies" in analyzers
                or entry.get("error_class") == "ConnectError"
            ):
                reason = (
                    "SkillSpector's known-vulnerability lookup (SC4) needs OSV.dev, which the "
                    "sandbox never reaches; only its built-in list was used (Trivy covers known "
                    "vulnerabilities)"
                )
            else:
                message = _str(entry.get("message")) or "analysis did not finish"
                reason = f"SkillSpector did not finish: {message}"[:300]
            recorder.not_assessed(
                self.rules,
                Subject.of_artifact(ArtifactRef(path)) if path else Subject.of_path(root),
                tool=ready.tool,
                reason=reason,
            )
        clean = sum(1 for p in known if _inside(p, root) and p not in flagged)
        recorder.passed("skill.finding", max(clean, 1))
