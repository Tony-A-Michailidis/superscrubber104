"""Licence policy, applied to whatever a unit or component declares."""

from collections.abc import Sequence

from airlock.analyzer import TOOL
from airlock.core.interfaces import Context
from airlock.core.model import Disposition, Severity, Subject
from airlock.licences import Declared, combine

_RULES = ("licence.denied", "licence.approval-required", "licence.unidentified", "licence.missing")


def check_licences(subject: Subject, declared: Sequence[Declared], ctx: Context) -> str | None:
    """Evaluate declared licences against the policy. Returns the combined SPDX expression."""
    recorder = ctx.recorder
    sources = [{"source": d.source, "identifier": d.identifier, "name": d.name} for d in declared]
    expression, conflict = combine(list(declared))
    if conflict:
        recorder.fail("licence.conflict", subject, tool=TOOL, detail={"declared": sources})
    else:
        recorder.passed("licence.conflict")

    if expression is None:
        rule = "licence.unidentified" if declared else "licence.missing"
        recorder.fail(rule, subject, tool=TOOL, detail={"declared": sources})
        for other in _RULES:
            if other != rule:
                recorder.passed(other)
        return None
    recorder.passed("licence.missing")
    unidentified = [d for d in declared if d.identifier is None]
    if unidentified:
        recorder.fail(
            "licence.unidentified",
            subject,
            tool=TOOL,
            detail={"declared": [s for s in sources if s["identifier"] is None]},
        )
    else:
        recorder.passed("licence.unidentified")

    # The policy's licence lists say what each licence needs; the finding's severity carries that
    # into the ordinary decision (high: block, medium: approval, low: warn).
    outcome = ctx.policy.licences.decide(expression)
    detail = {"expression": expression, "declared": sources}
    attributes = {"licence": expression}
    if outcome is Disposition.BLOCK:
        recorder.fail("licence.denied", subject, tool=TOOL, detail=detail, attributes=attributes)
    elif outcome in (Disposition.REQUIRE_APPROVAL, Disposition.WARN):
        severity = Severity.MEDIUM if outcome is Disposition.REQUIRE_APPROVAL else Severity.LOW
        recorder.fail(
            "licence.approval-required",
            subject,
            tool=TOOL,
            detail=detail,
            attributes=attributes,
            severity=severity,
        )
    else:
        recorder.passed("licence.denied")
        recorder.passed("licence.approval-required")
    return expression
