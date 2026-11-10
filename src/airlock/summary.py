"""Plain-text summary of an assessment for the terminal."""

from airlock.core.model import Assessment, Disposition, Result

_LABEL = {
    Disposition.BLOCK: "BLOCK",
    Disposition.REQUIRE_APPROVAL: "APPROVE",
    Disposition.WARN: "WARN",
    Disposition.ALLOW: "ok",
}
_RESULT = {Result.NOT_ASSESSED: " (not assessed)", Result.ERROR: " (check error)"}


def render(assessment: Assessment, *, verbose: bool = False) -> str:
    """One line per finding that needs attention, then counts and the verdict.

    Output is ASCII only, so it survives any console encoding.
    """
    decisions = {d.finding: d for d in assessment.decisions}
    rows = sorted(
        ((decisions[f.id], f) for f in assessment.findings if f.result is not Result.PASS),
        key=lambda row: (-row[0].disposition.rank, row[1].rule, row[1].subject.display),
    )
    lines = []
    for decision, finding in rows:
        if decision.disposition is Disposition.ALLOW and not verbose:
            continue
        label = _LABEL[decision.disposition]
        note = _RESULT.get(finding.result, "")
        lines.append(f"{label:<8}{finding.rule}{note}")
        lines.append(f"        {finding.subject.display}: {finding.title}")
        if finding.not_assessed_reason:
            lines.append(f"        reason: {finding.not_assessed_reason}")
        if decision.waiver:
            lines.append(f"        waived by {decision.waiver}")
    if lines:
        lines.append("")

    counts = assessment.summary.dispositions
    exercised = sum(1 for c in assessment.coverage if c.exercised)
    passed = sum(c.passed for c in assessment.coverage)
    lines.append(
        f"{exercised} of {len(assessment.coverage)} rules exercised, {passed} checks passed; "
        f"findings: {counts[Disposition.BLOCK]} block, "
        f"{counts[Disposition.REQUIRE_APPROVAL]} need approval, "
        f"{counts[Disposition.WARN]} warn, {counts[Disposition.ALLOW]} allowed"
    )
    lines.append(f"verdict: {assessment.summary.verdict.value.upper()}")
    return "\n".join(lines)
