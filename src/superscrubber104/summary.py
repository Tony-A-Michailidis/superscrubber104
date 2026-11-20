"""Plain-text summary of an assessment for the terminal."""

from superscrubber104.core.model import Assessment, Decision, Disposition, Result, Verdict

# A check that did not run is shown as such, never under the title of what it would have found
# ("Malware scanner reports a detection" when no scanner ran reads as a detection).
_NOT_RUN = {Result.NOT_ASSESSED: "not assessed: ", Result.ERROR: "check error: "}
_WIDTH = 16  # the longest label, NEEDS APPROVAL, and a space
_NEXT = {
    Verdict.PASSED: "",
    Verdict.NEEDS_APPROVAL: " - approvals are outstanding (superscrubber104 approve)",
    Verdict.BLOCKED: " - a policy blocker stands; it can be overridden by an approval quorum",
    Verdict.REFUSED: " - an integrity or authenticity check failed; this cannot be overridden",
}


def _label(decision: Decision, cleared: bool) -> str:
    if decision.disposition is Disposition.BLOCK:
        if decision.final:
            return "REFUSE"
        return "OVERRIDE" if cleared else "BLOCK"
    if decision.disposition is Disposition.REQUIRE_APPROVAL:
        return "APPROVED" if cleared else "NEEDS APPROVAL"
    return "WARN" if decision.disposition is Disposition.WARN else "ok"


def render(assessment: Assessment, *, verbose: bool = False) -> str:
    """One entry per finding that needs attention, then counts and the verdict.

    Each entry shows the finding id, which is what ``superscrubber104 approve --finding`` takes.
    Output is ASCII only, so it survives any console encoding.
    """
    decisions = {d.finding: d for d in assessment.decisions}
    counted: dict[str, list[str]] = {}
    for approval in assessment.approvals:
        if approval.counted:
            counted.setdefault(approval.finding, []).append(approval.holder or "?")

    rows = sorted(
        ((decisions[f.id], f) for f in assessment.findings if f.result is not Result.PASS),
        key=lambda row: (
            -row[0].final,
            -row[0].disposition.rank,
            row[1].rule,
            row[1].subject.display,
        ),
    )
    lines = []
    for decision, finding in rows:
        if decision.disposition is Disposition.ALLOW and not verbose:
            continue
        holders = sorted(set(counted.get(finding.id, [])))
        cleared = decision.clearable and len(holders) >= decision.approvals_required
        indent = " " * _WIDTH
        prefix = _NOT_RUN.get(finding.result, "")
        lines.append(f"{_label(decision, cleared):<{_WIDTH}}{prefix}{finding.rule}  [{finding.id}]")
        if prefix:
            why = finding.not_assessed_reason or str(
                finding.detail.get("error") or "see the assessment"
            )
            lines.append(f"{indent}{finding.subject.display}: the check did not run: {why}")
        else:
            lines.append(f"{indent}{finding.subject.display}: {finding.title}")
        if isinstance(hint := finding.detail.get("hint"), str):
            lines.append(f"{indent}hint: {hint}")
        if decision.waiver:
            lines.append(f"{indent}waived by policy waiver {decision.waiver}")
        if decision.clearable:
            who = f" ({', '.join(holders)})" if holders else ""
            lines.append(
                f"{indent}approvals: {len(holders)} of {decision.approvals_required} required{who}"
            )
    for approval in assessment.approvals:
        if not approval.counted:
            lines.append(f"NOT COUNTED approval of [{approval.finding}] by {approval.key_id}")
            lines.append(f"{' ' * _WIDTH}{approval.reason}")
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
    verdict = assessment.summary.verdict
    lines.append(f"verdict: {verdict.value.upper()}{_NEXT[verdict]}")
    return "\n".join(lines)
