"""The offline readiness report: what will break, what would leave, and the configuration to set."""

from collections import defaultdict

from superscrubber104.core.model import Assessment, Finding, Result, Summary, summarize

_IMPACTS = (
    ("will-break", "Will break on a network with no internet"),
    ("egress-risk", "Would send data out if it found a route"),
    ("informational", "For information"),
)


def offline_findings(assessment: Assessment) -> list[Finding]:
    return [
        f
        for f in assessment.findings
        if f.rule.startswith(("offline.", "runtime.")) and f.result is not Result.PASS
    ]


def offline_summary(assessment: Assessment) -> Summary:
    """The verdict over the offline and runtime findings only."""
    findings = offline_findings(assessment)
    ids = {f.id for f in findings}
    return summarize(findings, [d for d in assessment.decisions if d.finding in ids])


def recommended_configuration(findings: list[Finding]) -> tuple[dict[str, str], dict[str, str]]:
    """(environment variables, editor settings) that the findings say would fix them."""
    environment: dict[str, str] = {}
    settings: dict[str, str] = {}
    for finding in findings:
        fix = finding.detail.get("fix")
        for key, value in fix.items() if isinstance(fix, dict) else []:
            target = settings if "." in key else environment
            target.setdefault(
                str(key), str(value).lower() if isinstance(value, bool) else str(value)
            )
    return dict(sorted(environment.items())), dict(sorted(settings.items()))


def render_offline(assessment: Assessment) -> str:
    findings = offline_findings(assessment)
    if not findings:
        return "Offline readiness: nothing found that needs the network.\n"
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.attributes.get("impact", "informational")].append(finding)
    lines = ["Offline readiness", ""]
    for impact, title in _IMPACTS:
        if impact not in grouped:
            continue
        lines.append(f"{title}:")
        for finding in sorted(grouped[impact], key=lambda f: (f.rule, f.subject.display)):
            what = finding.detail.get("what") or finding.attributes.get("what") or finding.rule
            extra = finding.detail.get("model") or finding.detail.get("image") or ""
            suffix = f" ({extra})" if extra else ""
            lines.append(f"  {finding.severity.value:<8} {finding.subject.display}: {what}{suffix}")
        lines.append("")
    environment, settings = recommended_configuration(findings)
    if environment:
        lines.append("Recommended environment on the high side:")
        lines.extend(f"  {key}={value}" for key, value in environment.items())
        lines.append("")
    if settings:
        lines.append("Recommended editor settings:")
        lines.extend(f'  "{key}": {value}' for key, value in settings.items())
        lines.append("")
    return "\n".join(lines)
