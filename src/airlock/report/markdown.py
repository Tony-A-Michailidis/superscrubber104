"""The report as Markdown, for reviewers and for attaching to an assessment package."""

from collections.abc import Sequence

from airlock.core.model import Result
from airlock.core.serde import format_timestamp
from airlock.report.model import STANDING, Report, detail_text, rule_label

_VERDICT = {
    "passed": "PASSED",
    "needs-approval": "NEEDS APPROVAL: approvals are outstanding",
    "blocked": "BLOCKED: a policy blocker stands; an approval quorum can override it",
    "refused": "REFUSED: an integrity or authenticity check failed; nothing overrides it",
}


def cell(value: object) -> str:
    """Text safe inside a Markdown table cell."""
    text = str(value if value is not None else "")
    for char in ("\\", "|", "`", "*", "_", "<", ">", "[", "]"):
        text = text.replace(char, "\\" + char)
    return " ".join(text.split())


def _table(header: Sequence[str], rows: Sequence[Sequence[object]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return [*lines, ""]


def render_markdown(report: Report) -> str:
    out = [f"# {cell(report.title)}", ""]
    out.append(f"**Verdict: {_VERDICT.get(report.verdict, report.verdict)}**")
    out.append("")
    facts = [
        ["Stage", f"{report.stage} ({report.origin})"],
        ["Bundle", report.bundle_id or "-"],
        [
            "Transfer",
            f"{report.source or '?'} to {report.destination or '?'}"
            if report.source or report.destination
            else "-",
        ],
        ["Request", report.request_id or "-"],
        ["Manifest", report.manifest_digest or "-"],
        ["Policy", report.policy_digest],
        ["Tool", f"{report.tool.name} {report.tool.version}"],
        [
            "Assessed",
            f"{format_timestamp(report.started_at)} to {format_timestamp(report.finished_at)}",
        ],
        ["Controls", report.framework],
    ]
    if report.receipt is not None:
        facts.append(
            [
                "Receipt",
                f"{report.receipt.verdict.value} at {format_timestamp(report.receipt.verified_at)}",
            ]
        )
    out += _table(["", ""], facts)

    t = report.totals
    out += ["## Summary", ""]
    out.append(
        f"{t.get('rulesExercised', 0)} of {t.get('rules', 0)} rules exercised, "
        f"{t.get('checksPassed', 0)} checks passed, {t.get('notAssessed', 0)} not assessed. "
        f"Findings: {t.get('block', 0)} block, {t.get('require-approval', 0)} need approval, "
        f"{t.get('warn', 0)} warn, {t.get('allow', 0)} allowed."
    )
    if "artifacts" in t:
        out.append("")
        out.append(
            f"Inventory: {t['topLevelFiles']} files ({t['bytes']:,} bytes), "
            f"{t['archiveMembers']} archive members, {t['units']} units, "
            f"{t['components']} SBOM components."
        )
    out.append("")

    attention = [r for r in report.findings if r.action in STANDING]
    out += ["## Needs attention", ""]
    if attention:
        out += _table(
            ["Action", "Rule", "Subject", "Severity", "Finding", "Approvals"],
            [
                [
                    r.action,
                    rule_label(r.finding),
                    r.finding.subject.display,
                    r.finding.severity.value,
                    r.finding.id,
                    f"{len(r.approvals)} of {r.required}" if r.required else "",
                ]
                for r in attention
            ],
        )
    else:
        out += ["Nothing stands in the way.", ""]

    out += ["## Controls", ""]
    out.append(
        "What airlock evidenced for each control, and what it found. A control's status is "
        "never 'satisfied': airlock covers part of a control; the assessor judges the system."
    )
    out.append("")
    out += _table(
        [
            "Control",
            "Title",
            "Status",
            "Passed",
            "Failed",
            "Not assessed",
            "Evidence airlock provides",
        ],
        [
            [c.id, c.title, c.status, c.passed, c.failed, c.not_assessed + c.errors, c.provided]
            for c in report.controls
        ],
    )

    if report.units:
        out += ["## Units", ""]
        out += _table(
            ["Kind", "Name", "Root", "Members", "Summary"],
            [
                [
                    u.kind,
                    u.name,
                    u.root,
                    u.members,
                    "; ".join(f"{k}: {v}" for k, v in u.summary.items()),
                ]
                for u in report.units
            ],
        )
    if report.plugins:
        out += ["## Scanners and feeds", ""]
        out += _table(
            ["Plugin", "Usable", "Version", "Database", "Age (h)", "Pinned", "Reason"],
            [
                [
                    p.name,
                    "yes" if p.present and p.reason is None else "no",
                    p.version or "",
                    p.data_version or "",
                    p.data_age_seconds // 3600 if p.data_age_seconds is not None else "",
                    {None: "", True: "yes", False: "no"}[p.pinned],
                    p.reason or "",
                ]
                for p in report.plugins
            ],
        )
    not_assessed = [r for r in report.findings if r.finding.result is Result.NOT_ASSESSED]
    if not_assessed:
        out += ["## Not assessed", ""]
        out += _table(
            ["Rule", "Subject", "Reason"],
            [
                [r.finding.rule, r.finding.subject.display, r.finding.not_assessed_reason]
                for r in not_assessed
            ],
        )
    out += ["## All findings", ""]
    rows = [r for r in report.findings if r.finding.result is not Result.NOT_ASSESSED]
    if rows:
        out += _table(
            ["Action", "Rule", "Subject", "Severity", "Controls", "Detail", "Finding"],
            [
                [
                    r.action + (f" (waiver {r.waiver})" if r.waiver else ""),
                    r.finding.rule,
                    r.finding.subject.display,
                    r.finding.severity.value,
                    ", ".join(r.finding.controls),
                    detail_text(r.finding.detail),
                    r.finding.id,
                ]
                for r in rows
            ],
        )
    else:
        out += ["None.", ""]
    if report.approvals:
        out += ["## Approvals", ""]
        out += _table(
            ["Finding", "Approver", "Counted", "Justification"],
            [
                [
                    a.finding,
                    a.holder or a.key_id,
                    "yes" if a.counted else f"no: {a.reason}",
                    a.justification,
                ]
                for a in report.approvals
            ],
        )
    if report.kinds:
        out += ["## Inventory by kind", ""]
        out += _table(["Kind", "Files"], [[k, n] for k, n in report.kinds.items()])
    return "\n".join(out).rstrip() + "\n"
