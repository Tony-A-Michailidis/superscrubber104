"""The report: one structure that every format (Markdown, HTML, JSON, OSCAL) is rendered from.

Built from an assessment and the analysis it was made with. It adds nothing that is not in
them: totals, rows grouped for reading, and the control matrix. The matrix records, per control,
which rules produced evidence and what they found. It does not say a control is satisfied:
airlock evidences part of a control, the assessor judges the system.
"""

import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from airlock import bundle as layout
from airlock.core.canonical import JSON, jsonable
from airlock.core.controls import ControlCatalog
from airlock.core.errors import ConfigError
from airlock.core.model import (
    API_VERSION,
    Analysis,
    ApprovalRecord,
    Assessment,
    Coverage,
    Disposition,
    EntryType,
    Finding,
    PluginStatus,
    Receipt,
    Result,
    ToolRef,
    Unit,
)
from airlock.core.serde import from_data
from airlock.core.signing import Envelope
from airlock.report.evidence import PROVIDED

# Control statuses, from most to least in need of attention.
STATUS_FINDINGS = "findings"  # a failing check stands (block or approval)
STATUS_NOTED = "noted"  # failing checks, all of them warnings or allowed
STATUS_NOT_ASSESSED = "not-assessed"  # its checks could not run
STATUS_PARTIAL = "partly-assessed"  # some checks ran, some could not
STATUS_CLEAR = "no-findings"  # its checks ran and found nothing
STATUS_UNEXERCISED = "not-exercised"  # it has rules, none applied to this delivery
STATUS_NO_RULES = "no-rules"  # nothing in airlock evidences it


@dataclass(frozen=True, slots=True)
class Context:
    """What the assessment is about, from the files around it."""

    origin: str  # "bundle (packing side, unverified)", "verify", "inspect"
    bundle_id: str | None = None
    source: str | None = None
    destination: str | None = None
    request_id: str | None = None
    request_title: str | None = None
    receipt: Receipt | None = None


@dataclass(frozen=True, slots=True)
class FindingRow:
    finding: Finding
    action: str  # REFUSE, BLOCK, OVERRIDE, APPROVE, APPROVED, WARN, ok
    approvals: tuple[str, ...] = ()  # holders whose approval counted
    required: int = 0
    waiver: str | None = None


@dataclass(frozen=True, slots=True)
class ControlRow:
    id: str
    title: str
    status: str
    provided: str
    rules: tuple[str, ...]
    passed: int
    failed: int
    not_assessed: int
    errors: int
    findings: tuple[str, ...]  # ids of non-passing findings


@dataclass(frozen=True, slots=True)
class UnitRow:
    kind: str
    name: str
    root: str
    members: int
    digest: str
    summary: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Report:
    title: str
    stage: str
    origin: str
    verdict: str
    tool: ToolRef
    policy_digest: str
    started_at: datetime
    finished_at: datetime
    framework: str
    totals: Mapping[str, int]
    kinds: Mapping[str, int]
    components: Mapping[str, int]
    units: tuple[UnitRow, ...]
    plugins: tuple[PluginStatus, ...]
    findings: tuple[FindingRow, ...]
    controls: tuple[ControlRow, ...]
    coverage: tuple[Coverage, ...]
    approvals: tuple[ApprovalRecord, ...]
    manifest_digest: str | None = None
    bundle_id: str | None = None
    source: str | None = None
    destination: str | None = None
    request_id: str | None = None
    receipt: Receipt | None = None
    api_version: str = API_VERSION
    kind: str = "Report"


@dataclass(frozen=True, slots=True)
class Source:
    analysis: Analysis | None
    assessment: Assessment
    context: Context


# --- loading ------------------------------------------------------------------------------------


def _read(path: Path, cls: type, what: str):  # type: ignore[no-untyped-def]
    try:
        return from_data(cls, json.loads(path.read_bytes()))
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"cannot read {what} {path}: {exc}") from exc


def _request(path: Path) -> tuple[str | None, str | None]:
    from airlock.core.request import load_request

    if not path.is_file():
        return None, None
    try:
        request = load_request(path)
    except ConfigError:
        return None, None
    return request.id, request.title


def load_source(path: Path) -> Source:
    """A bundle, a verify output directory, an inspect output directory, or an assessment file."""
    if path.is_dir() and (path / layout.DESCRIPTOR).is_file():
        analysis = _read(path / layout.ANALYSIS, Analysis, "analysis")
        assessment = _read(path / layout.ASSESSMENT, Assessment, "assessment")
        provenance = None
        try:
            envelope = Envelope.from_data(json.loads((path / layout.STATEMENT).read_bytes()))
            provenance = layout.parse_statement(envelope.payload)[1]
        except (OSError, ValueError, TypeError, ConfigError):
            provenance = None
        request_id, title = _request(path / layout.REQUEST)
        return Source(
            analysis,
            assessment,
            Context(
                origin="bundle (packing side; run airlock verify for this side's own report)",
                bundle_id=provenance.bundle_id if provenance else None,
                source=provenance.source if provenance else None,
                destination=provenance.destination if provenance else None,
                request_id=request_id,
                request_title=title,
            ),
        )
    if path.is_dir():
        for stage in ("verify", "inspect"):
            assessment_path = path / f"assessment.{stage}.json"
            if assessment_path.is_file():
                analysis_path = path / f"analysis.{stage}.json"
                receipt = None
                if (path / "receipt.json").is_file():
                    receipt = _read(path / "receipt.json", Receipt, "receipt")
                elif (path / "receipt.dsse.json").is_file():
                    envelope = Envelope.from_data(
                        json.loads((path / "receipt.dsse.json").read_bytes())
                    )
                    receipt = from_data(Receipt, json.loads(envelope.payload))
                request_id, title = _request(path / layout.REQUEST)
                return Source(
                    _read(analysis_path, Analysis, "analysis") if analysis_path.is_file() else None,
                    _read(assessment_path, Assessment, "assessment"),
                    Context(
                        origin={
                            "verify": "this side's verification",
                            "inspect": "inspection in place",
                        }[stage],
                        bundle_id=receipt.bundle_id if receipt else None,
                        source=receipt.source if receipt else None,
                        destination=receipt.enclave if receipt else None,
                        request_id=request_id or (receipt.request_id if receipt else None),
                        request_title=title,
                        receipt=receipt,
                    ),
                )
        raise ConfigError(f"{path} holds no bundle and no assessment.verify/inspect.json")
    return Source(None, _read(path, Assessment, "assessment"), Context(origin="assessment file"))


# --- building -----------------------------------------------------------------------------------


def _action(decision_disposition: Disposition, final: bool, cleared: bool) -> str:
    if decision_disposition is Disposition.BLOCK:
        return "REFUSE" if final else ("OVERRIDE" if cleared else "BLOCK")
    if decision_disposition is Disposition.REQUIRE_APPROVAL:
        return "APPROVED" if cleared else "APPROVE"
    return "WARN" if decision_disposition is Disposition.WARN else "ok"


def _findings(assessment: Assessment) -> list[FindingRow]:
    decisions = {d.finding: d for d in assessment.decisions}
    counted: dict[str, set[str]] = defaultdict(set)
    for approval in assessment.approvals:
        if approval.counted:
            counted[approval.finding].add(approval.holder or approval.key_id or "?")
    rows = []
    for finding in assessment.findings:
        if finding.result is Result.PASS:
            continue
        decision = decisions.get(finding.id)
        if decision is None:
            continue
        holders = tuple(sorted(counted.get(finding.id, set())))
        cleared = decision.clearable and len(holders) >= decision.approvals_required
        rows.append(
            FindingRow(
                finding,
                _action(decision.disposition, decision.final, cleared),
                holders,
                decision.approvals_required if decision.clearable else 0,
                decision.waiver,
            )
        )
    order = {
        "REFUSE": 0,
        "BLOCK": 1,
        "APPROVE": 2,
        "OVERRIDE": 3,
        "APPROVED": 4,
        "WARN": 5,
        "ok": 6,
    }
    return sorted(rows, key=lambda r: (order[r.action], r.finding.rule, r.finding.subject.display))


def _controls(
    assessment: Assessment, rows: Sequence[FindingRow], catalog: ControlCatalog
) -> list[ControlRow]:
    rules_for: dict[str, list[Coverage]] = defaultdict(list)
    for coverage in assessment.coverage:
        for control in coverage.controls:
            rules_for[control.split("(", 1)[0]].append(coverage)
    findings_for: dict[str, list[FindingRow]] = defaultdict(list)
    for row in rows:
        for control in row.finding.controls:
            findings_for[control.split("(", 1)[0]].append(row)
    ids = sorted({c.id for c in catalog} | set(rules_for), key=_control_key)
    out = []
    for control_id in ids:
        mapped = rules_for.get(control_id, [])
        found = findings_for.get(control_id, [])
        passed = sum(c.passed for c in mapped)
        failed = sum(c.failed for c in mapped)
        not_assessed = sum(c.not_assessed for c in mapped)
        errors = sum(c.errors for c in mapped)
        standing = [r for r in found if r.action in ("REFUSE", "BLOCK", "APPROVE")]
        noted = [r for r in found if r.finding.result is Result.FAIL]
        if not mapped:
            status = STATUS_NO_RULES
        elif standing:
            status = STATUS_FINDINGS
        elif noted:
            status = STATUS_NOTED
        elif (not_assessed or errors) and not passed:
            status = STATUS_NOT_ASSESSED
        elif not_assessed or errors:
            status = STATUS_PARTIAL
        elif passed:
            status = STATUS_CLEAR
        else:
            status = STATUS_UNEXERCISED
        title = catalog.get(control_id).title if control_id in catalog else ""
        out.append(
            ControlRow(
                id=control_id,
                title=title,
                status=status,
                provided=PROVIDED.get(control_id, ""),
                rules=tuple(sorted({c.rule for c in mapped})),
                passed=passed,
                failed=failed,
                not_assessed=not_assessed,
                errors=errors,
                findings=tuple(r.finding.id for r in found),
            )
        )
    return out


def _control_key(control_id: str) -> tuple[str, int]:
    family, _, number = control_id.partition("-")
    digits = "".join(ch for ch in number if ch.isdigit())
    return family, int(digits) if digits else 0


def _short(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(_short(v) for v in value[:6]) + (" ..." if len(value) > 6 else "")
    if isinstance(value, dict):
        return ", ".join(f"{k} {_short(v)}" for k, v in list(value.items())[:6])
    return str(value)


# Attributes worth a reader's attention, per unit kind: (label, path into the attributes).
_SUMMARY: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "model-package": (
        ("formats", ("weights", "formats")),
        ("architecture", ("identity", "architecture")),
        ("licence", ("licence", "expression")),
        ("provenance", ("provenance", "method")),
        ("signature", ("signature", "status")),
    ),
    "container-image": (("images", ("images",)),),
    "python-environment": (
        ("requirements", ("requirements",)),
        ("unresolvable", ("unresolvable",)),
        ("hashed", ("hashed",)),
    ),
    "node-environment": (("locked", ("locked",)), ("unresolvable", ("unresolvable",))),
    **{
        kind: (
            ("requirements", ("requirements",)),
            ("unresolvable", ("unresolvable",)),
            ("hash checked", ("hashChecked",)),
        )
        for kind in (
            "jvm-environment",
            "go-environment",
            "rust-environment",
            "dotnet-environment",
            "terraform-environment",
        )
    },
    "vm-image": (
        ("format", ("format",)),
        ("virtual size", ("virtualSize",)),
        ("depends on", ("dependsOn",)),
        ("os", ("glance", "os_distro")),
    ),
    "repo-mirror": (
        ("format", ("format",)),
        ("packages", ("packages",)),
        ("verified", ("verifiedPackages",)),
        ("missing", ("missing",)),
        ("snapshots", ("snapshots",)),
    ),
    "dataset": (("rows", ("rows",)), ("formats", ("formats",)), ("licence", ("licence",))),
    "knowledge-base": (
        ("stores", ("stores",)),
        ("dimensions", ("dimensions",)),
        ("documents", ("documents",)),
        ("embedding models", ("embeddingModels",)),
    ),
    "runtime-profile": (("server", ("declared", "server", "name")),),
    "zarf-package": (
        ("version", ("version",)),
        ("components", ("componentNames",)),
        ("signature", ("signature", "status")),
        ("differential base", ("differential", "base")),
    ),
}


def _unit_row(unit: Unit) -> UnitRow:
    summary: dict[str, str] = {}
    for label, path in _SUMMARY.get(unit.kind.value, ()):
        value: object = unit.attributes
        for key in path:
            value = value.get(key) if isinstance(value, Mapping) else None
        if value in (None, [], {}, ""):
            continue
        if label == "images" and isinstance(value, list):
            value = [v.get("name") for v in value if isinstance(v, Mapping)]
        summary[label] = _short(value)
    return UnitRow(
        unit.kind.value, unit.name, unit.root.display, len(unit.members), unit.digest, summary
    )


def build_report(source: Source, catalog: ControlCatalog | None = None) -> Report:
    catalog = catalog or ControlCatalog.builtin()
    assessment, analysis, context = source.assessment, source.analysis, source.context
    rows = _findings(assessment)
    totals: dict[str, int] = {
        "findings": len(assessment.findings),
        "rules": len(assessment.coverage),
        "rulesExercised": sum(1 for c in assessment.coverage if c.exercised),
        "checksPassed": sum(c.passed for c in assessment.coverage),
        "notAssessed": sum(1 for f in assessment.findings if f.result is Result.NOT_ASSESSED),
    }
    for disposition, count in assessment.summary.dispositions.items():
        totals[disposition.value] = count
    kinds: Counter[str] = Counter()
    components: Counter[str] = Counter()
    units: list[UnitRow] = []
    if analysis is not None:
        files = [a for a in analysis.artifacts if a.entry_type is EntryType.FILE]
        totals["artifacts"] = len(analysis.artifacts)
        totals["topLevelFiles"] = sum(1 for a in files if not a.ref.member)
        totals["archiveMembers"] = sum(1 for a in files if a.ref.member)
        totals["bytes"] = sum(a.size or 0 for a in files if not a.ref.member)
        totals["units"] = len(analysis.units)
        totals["components"] = len(analysis.components)
        kinds.update(a.kinds[0] if a.kinds else "unclassified" for a in files)
        components.update(c.type.value for c in analysis.components)
        units = [_unit_row(u) for u in analysis.units]
    title = context.request_title or (
        f"Bundle {context.bundle_id}" if context.bundle_id else "airlock assessment"
    )
    return Report(
        title=title,
        stage=assessment.stage.value,
        origin=context.origin,
        verdict=assessment.summary.verdict.value,
        tool=assessment.tool,
        policy_digest=assessment.policy_digest,
        started_at=assessment.started_at,
        finished_at=assessment.finished_at,
        framework=catalog.framework,
        totals=totals,
        kinds=dict(sorted(kinds.items())),
        components=dict(sorted(components.items())),
        units=tuple(sorted(units, key=lambda u: (u.kind, u.root))),
        plugins=assessment.plugins,
        findings=tuple(rows),
        controls=tuple(_controls(assessment, rows, catalog)),
        coverage=assessment.coverage,
        approvals=assessment.approvals,
        manifest_digest=assessment.manifest_digest,
        bundle_id=context.bundle_id,
        source=context.source,
        destination=context.destination,
        request_id=context.request_id,
        receipt=context.receipt,
    )


def detail_text(detail: Mapping[str, JSON], limit: int = 300) -> str:
    """A finding's detail as one readable line."""
    text = json.dumps(jsonable(dict(detail)), sort_keys=True, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 3] + "..."
