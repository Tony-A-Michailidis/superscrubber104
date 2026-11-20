"""The report as OSCAL 1.1.2 assessment results.

* Each control with evidence gets an **observation** summarising the rules that ran and what they
  found, and each non-passing finding gets an observation of its own.
* A control with standing or noted findings, or whose checks could not run, gets an OSCAL
  **finding** with state ``not-satisfied`` (reason ``fail``, or ``other`` for not assessed),
  linked to its observations.
* A control whose checks ran and found nothing gets no OSCAL finding: superscrubber104 evidences
  part of a control, and only the assessor can say a control is satisfied for the system.

Identifiers are UUID v5 derived from the content, so the same assessment gives the same document.
"""

import json
import uuid
from typing import Any

from superscrubber104.core.model import Result
from superscrubber104.core.serde import format_timestamp
from superscrubber104.report.model import (
    STATUS_CLEAR,
    STATUS_NO_RULES,
    STATUS_NOT_ASSESSED,
    STATUS_PARTIAL,
    STATUS_UNEXERCISED,
    Report,
    detail_text,
)

_NS = "urn:superscrubber104"
_ROOT = uuid.UUID("0b8b1c56-2f0e-5a4c-8a7d-3f6e1d2c4b5a")


def control_id(control: str) -> str:
    """NIST id to OSCAL form: ``SI-7`` -> ``si-7``, ``SI-7(1)`` -> ``si-7.1``."""
    base, _, enhancement = control.partition("(")
    return base.lower() + (f".{enhancement.rstrip(')')}" if enhancement else "")


def render_oscal(report: Report) -> str:
    seed = f"{report.policy_digest}|{report.manifest_digest}|{format_timestamp(report.finished_at)}"

    def uid(*parts: str) -> str:
        return str(uuid.uuid5(_ROOT, "|".join((seed, *parts))))

    finished = format_timestamp(report.finished_at)
    finding_obs: dict[str, str] = {}
    observations: list[dict[str, Any]] = []
    for row in report.findings:
        f = row.finding
        obs_id = uid("observation", f.id)
        finding_obs[f.id] = obs_id
        description = f"{f.subject.display}: {f.title}."
        if f.result is Result.NOT_ASSESSED:
            description += f" Not assessed: {f.not_assessed_reason}."
        elif f.detail:
            description += f" Detail: {detail_text(f.detail, 600)}"
        observations.append(
            {
                "uuid": obs_id,
                "title": f"{f.rule} on {f.subject.display}"[:250],
                "description": description,
                "props": [
                    {"name": "rule", "ns": _NS, "value": f.rule},
                    {"name": "result", "ns": _NS, "value": f.result.value},
                    {"name": "severity", "ns": _NS, "value": f.severity.value},
                    {"name": "action", "ns": _NS, "value": row.action},
                    {"name": "finding-id", "ns": _NS, "value": f.id},
                ],
                "methods": ["TEST"],
                "types": ["finding"],
                "collected": finished,
            }
        )
    findings: list[dict[str, Any]] = []
    reviewed: list[dict[str, str]] = []
    for control in report.controls:
        if control.status in (STATUS_NO_RULES, STATUS_UNEXERCISED):
            continue
        cid = control_id(control.id)
        reviewed.append({"control-id": cid})
        summary_id = uid("evidence", control.id)
        observations.append(
            {
                "uuid": summary_id,
                "title": f"superscrubber104 evidence for {control.id} {control.title}".strip(),
                "description": (
                    f"{control.provided} Rules: {', '.join(control.rules)}. "
                    f"Checks passed: {control.passed}; failed: {control.failed}; "
                    f"not assessed: {control.not_assessed}; errors: {control.errors}."
                ),
                "props": [{"name": "status", "ns": _NS, "value": control.status}],
                "methods": ["TEST"],
                "types": ["control-objective"],
                "collected": finished,
            }
        )
        if control.status == STATUS_CLEAR:
            continue
        # findings or noted: checks failed; not assessed or partly: they could not run
        reason = "other" if control.status in (STATUS_NOT_ASSESSED, STATUS_PARTIAL) else "fail"
        related = [{"observation-uuid": summary_id}] + [
            {"observation-uuid": finding_obs[f]} for f in control.findings if f in finding_obs
        ]
        findings.append(
            {
                "uuid": uid("finding", control.id),
                "title": f"{control.id} {control.title}".strip(),
                "description": (
                    f"superscrubber104 checks mapped to {control.id}: status {control.status}. "
                    f"{len(control.findings)} non-passing result(s)."
                ),
                "target": {
                    "type": "objective-id",
                    "target-id": f"{cid}_obj",
                    "status": {"state": "not-satisfied", "reason": reason},
                },
                "related-observations": related,
            }
        )
    selections: list[dict[str, object]] = (
        [{"include-controls": reviewed}] if reviewed else [{"include-all": {}}]
    )
    document = {
        "assessment-results": {
            "uuid": uid("assessment-results"),
            "metadata": {
                "title": f"superscrubber104 {report.stage}: {report.title}",
                "last-modified": finished,
                "version": report.tool.version,
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "verdict", "ns": _NS, "value": report.verdict},
                    {"name": "policy-digest", "ns": _NS, "value": report.policy_digest},
                ]
                + (
                    [{"name": "manifest-digest", "ns": _NS, "value": report.manifest_digest}]
                    if report.manifest_digest
                    else []
                ),
                "remarks": (
                    "Generated by superscrubber104. Controls whose checks ran without findings are "
                    "recorded "
                    "as observations only; whether a control is satisfied is the assessor's call."
                ),
            },
            "import-ap": {"href": f"{_NS}:policy:{report.policy_digest}"},
            "results": [
                {
                    "uuid": uid("result"),
                    "title": f"superscrubber104 {report.stage} ({report.origin})",
                    "description": f"Verdict: {report.verdict}. Framework: {report.framework}.",
                    "start": format_timestamp(report.started_at),
                    "end": finished,
                    "reviewed-controls": {"control-selections": selections},
                    "observations": observations,
                    **({"findings": findings} if findings else {}),
                }
            ],
        }
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
