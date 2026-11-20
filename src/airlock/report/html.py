"""The report as one self-contained HTML page: no scripts, no external styles, fonts or images.

It is opened on disconnected networks and stored with assessment evidence, so it must render
from the file alone. Every value from the delivery is escaped: file names and finding details
come from content that crossed and are never trusted as markup.
"""

from html import escape

from airlock.core.model import Result
from airlock.core.serde import format_timestamp
from airlock.report.model import STANDING, Report, detail_text, rule_label

_STYLE = """
:root { --bg: #ffffff; --fg: #1d2330; --muted: #5b6475; --line: #d9dee7; --head: #f3f5f8;
  --refuse: #8b1a1a; --block: #b42318; --approve: #b54708; --warn: #8a6d00; --ok: #067647; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14171c; --fg: #e6e9ef; --muted: #9aa3b2; --line: #2c323c;
    --head: #1c2027; --refuse: #ff8a80; --block: #ff8a80; --approve: #ffb74d;
    --warn: #e6c84f; --ok: #6fd39b; } }
body { background: var(--bg); color: var(--fg); margin: 0 auto; max-width: 1180px;
  padding: 24px 16px; font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
h1 { font-size: 22px; margin: 0 0 8px; } h2 { font-size: 17px; margin: 28px 0 8px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; }
th, td { border-bottom: 1px solid var(--line); padding: 6px 8px; text-align: left;
  vertical-align: top; }
th { background: var(--head); font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
code, .mono { font-family: ui-monospace, Consolas, monospace; font-size: 12.5px;
  word-break: break-all; }
.muted { color: var(--muted); }
.verdict { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 700;
  border: 1px solid; }
.REFUSE, .refused { color: var(--refuse); } .BLOCK, .blocked, .findings { color: var(--block); }
.NEEDS-APPROVAL, .needs-approval, .not-assessed, .partly-assessed { color: var(--approve); }
.WARN, .noted { color: var(--warn); }
.ok, .passed, .no-findings, .OVERRIDE, .APPROVED { color: var(--ok); }
details { margin: 8px 0; } summary { cursor: pointer; font-weight: 600; }
"""

_CSP = "default-src 'none'; style-src 'unsafe-inline'"


def _row(
    cells: list[object], numeric: set[int] | None = None, classes: dict[int, str] | None = None
) -> str:
    parts = []
    for index, value in enumerate(cells):
        attrs = []
        if numeric and index in numeric:
            attrs.append('class="num"')
        elif classes and index in classes:
            attrs.append(f'class="{escape(classes[index])}"')
        text = escape(str(value if value is not None else ""))
        parts.append(f"<td {' '.join(attrs)}>{text}</td>" if attrs else f"<td>{text}</td>")
    return "<tr>" + "".join(parts) + "</tr>"


def _table(header: list[str], rows: list[str]) -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in header)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def render_html(report: Report) -> str:
    t = report.totals
    body = [f"<h1>{escape(report.title)}</h1>"]
    verdict = escape(report.verdict)
    body.append(f'<p><span class="verdict {verdict}">{verdict.upper()}</span></p>')
    facts = [
        ("Stage", f"{report.stage} ({report.origin})"),
        ("Bundle", report.bundle_id or "-"),
        ("Transfer", f"{report.source or '?'} to {report.destination or '?'}"),
        ("Request", report.request_id or "-"),
        ("Manifest", report.manifest_digest or "-"),
        ("Policy", report.policy_digest),
        ("Tool", f"{report.tool.name} {report.tool.version}"),
        (
            "Assessed",
            f"{format_timestamp(report.started_at)} to {format_timestamp(report.finished_at)}",
        ),
        ("Controls", report.framework),
    ]
    body.append(_table(["", ""], [_row([k, v]) for k, v in facts]))
    body.append("<h2>Summary</h2>")
    body.append(
        f"<p>{t.get('rulesExercised', 0)} of {t.get('rules', 0)} rules exercised, "
        f"{t.get('checksPassed', 0)} checks passed, {t.get('notAssessed', 0)} not assessed. "
        f"Findings: {t.get('block', 0)} block, {t.get('require-approval', 0)} need approval, "
        f"{t.get('warn', 0)} warn, {t.get('allow', 0)} allowed.</p>"
    )
    if "artifacts" in t:
        body.append(
            f"<p>Inventory: {t['topLevelFiles']} files ({t['bytes']:,} bytes), "
            f"{t['archiveMembers']} archive members, {t['units']} units, "
            f"{t['components']} SBOM components.</p>"
        )
    attention = [r for r in report.findings if r.action in STANDING]
    body.append("<h2>Needs attention</h2>")
    if attention:
        body.append(
            _table(
                ["Action", "Rule", "Subject", "Severity", "Detail", "Finding"],
                [
                    _row(
                        [
                            r.action,
                            rule_label(r.finding),
                            r.finding.subject.display,
                            r.finding.severity.value,
                            detail_text(r.finding.detail),
                            r.finding.id,
                        ],
                        classes={0: r.action.replace(" ", "-")},
                    )
                    for r in attention
                ],
            )
        )
    else:
        body.append("<p>Nothing stands in the way.</p>")
    body.append("<h2>Controls</h2>")
    body.append(
        '<p class="muted">What airlock evidenced for each control, and what it found. A '
        "status is never 'satisfied': airlock covers part of a control; the assessor judges "
        "the system.</p>"
    )
    body.append(
        _table(
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
                _row(
                    [
                        c.id,
                        c.title,
                        c.status,
                        c.passed,
                        c.failed,
                        c.not_assessed + c.errors,
                        c.provided,
                    ],
                    numeric={3, 4, 5},
                    classes={2: c.status},
                )
                for c in report.controls
            ],
        )
    )
    if report.units:
        body.append("<h2>Units</h2>")
        body.append(
            _table(
                ["Kind", "Name", "Root", "Members", "Summary"],
                [
                    _row(
                        [
                            u.kind,
                            u.name,
                            u.root,
                            u.members,
                            "; ".join(f"{k}: {v}" for k, v in u.summary.items()),
                        ],
                        numeric={3},
                    )
                    for u in report.units
                ],
            )
        )
    if report.plugins:
        body.append("<h2>Scanners and feeds</h2>")
        body.append(
            _table(
                ["Plugin", "Usable", "Version", "Database", "Age (h)", "Reason"],
                [
                    _row(
                        [
                            p.name,
                            "yes" if p.present and p.reason is None else "no",
                            p.version or "",
                            p.data_version or "",
                            p.data_age_seconds // 3600 if p.data_age_seconds is not None else "",
                            p.reason or "",
                        ],
                        numeric={4},
                    )
                    for p in report.plugins
                ],
            )
        )
    not_assessed = [r for r in report.findings if r.finding.result is Result.NOT_ASSESSED]
    if not_assessed:
        body.append("<h2>Not assessed</h2>")
        body.append(
            _table(
                ["Rule", "Subject", "Reason"],
                [
                    _row([r.finding.rule, r.finding.subject.display, r.finding.not_assessed_reason])
                    for r in not_assessed
                ],
            )
        )
    rows = [r for r in report.findings if r.finding.result is not Result.NOT_ASSESSED]
    body.append(f"<details><summary>All findings ({len(rows)})</summary>")
    body.append(
        _table(
            ["Action", "Rule", "Subject", "Severity", "Controls", "Detail", "Finding"],
            [
                _row(
                    [
                        r.action + (f" (waiver {r.waiver})" if r.waiver else ""),
                        r.finding.rule,
                        r.finding.subject.display,
                        r.finding.severity.value,
                        ", ".join(r.finding.controls),
                        detail_text(r.finding.detail),
                        r.finding.id,
                    ],
                    classes={0: r.action.replace(" ", "-")},
                )
                for r in rows
            ],
        )
    )
    body.append("</details>")
    if report.approvals:
        body.append("<h2>Approvals</h2>")
        body.append(
            _table(
                ["Finding", "Approver", "Counted", "Justification"],
                [
                    _row(
                        [
                            a.finding,
                            a.holder or a.key_id,
                            "yes" if a.counted else f"no: {a.reason}",
                            a.justification,
                        ]
                    )
                    for a in report.approvals
                ],
            )
        )
    body.append(f"<details><summary>Rule coverage ({len(report.coverage)} rules)</summary>")
    body.append(
        _table(
            ["Rule", "Controls", "Passed", "Failed", "Not assessed", "Errors"],
            [
                _row(
                    [c.rule, ", ".join(c.controls), c.passed, c.failed, c.not_assessed, c.errors],
                    numeric={2, 3, 4, 5},
                )
                for c in report.coverage
            ],
        )
    )
    body.append("</details>")
    if report.kinds:
        body.append(f"<details><summary>Inventory by kind ({len(report.kinds)} kinds)</summary>")
        body.append(
            _table(["Kind", "Files"], [_row([k, n], numeric={1}) for k, n in report.kinds.items()])
        )
        body.append("</details>")
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        f"<title>{escape(report.title)}</title><style>{_STYLE}</style></head>"
        f"<body>{''.join(body)}</body></html>\n"
    )
