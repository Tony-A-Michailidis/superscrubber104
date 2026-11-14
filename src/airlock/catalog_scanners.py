"""Built-in rules for the basics every delivery gets: secrets, executables and active content in
documents, and the results of external scanners (malware, vulnerabilities).

Scanners are optional plugins. When one is not configured, or cannot be trusted, its checks are
recorded as *not assessed*, never left out. A scanner binary or database that does not match the
hash the policy pins is a hash mismatch, so ``plugin.integrity.mismatch`` is final: a tampered
scanner must not be able to wave content through, and no approval changes that.
"""

from airlock.core.model import Severity
from airlock.core.rules import RuleSpec

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO  # noqa: E741


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    controls: tuple[str, ...],
    rationale: str,
    *,
    final: bool = False,
    remediation: str = "",
) -> RuleSpec:
    return RuleSpec(rule_id, "1", title, severity, controls, rationale, remediation, final)


PLUGINS = (
    _rule(
        "plugin.integrity.mismatch",
        "Scanner binary or database does not match the hash the policy pins",
        C,
        ("SI-7", "SR-11", "SI-3"),
        "Scanners cross the air gap too. A scanner that is not the one the site approved could "
        "report anything, so it is not run, and the mismatch is a hash mismatch like any other.",
        final=True,
        remediation="Reinstall the scanner or its database from a verified bundle, or update the "
        "pinned hashes after an approved upgrade.",
    ),
    _rule(
        "plugin.unpinned",
        "Scanner runs without a pinned hash",
        L,
        ("SI-7", "CM-6"),
        "Without a pinned hash the evidence cannot show which scanner build or database "
        "produced the result.",
        remediation="Add binarySha256 and files to the plugin's policy entry.",
    ),
    _rule(
        "plugin.version.unsupported",
        "Scanner is older than the policy's minimum version",
        H,
        ("SI-3", "RA-5", "SA-22"),
        "An old scanner misses formats and detections; it is not run.",
    ),
    _rule(
        "plugin.data.stale",
        "Scanner database or feed is older than the policy allows",
        M,
        ("SI-3", "RA-5"),
        "On a disconnected network, databases age between transfers. A scan against old data "
        "misses what was found since.",
        remediation="Bring a current database across, then rescan.",
    ),
    _rule(
        "plugin.scan.error",
        "Scanner failed or produced output that could not be read",
        H,
        ("SI-3", "RA-5"),
        "Content the scanner did not finish with has not been scanned.",
    ),
    _rule(
        "malware.detected",
        "Malware scanner reports a detection",
        C,
        ("SI-3",),
        "Known malicious code, or a heuristic detection, in content about to cross.",
        remediation="Remove the file and find out how it got into the delivery.",
    ),
    _rule(
        "vuln.component.known",
        "Component has a known vulnerability",
        H,
        ("RA-5", "SI-2"),
        "Known vulnerabilities cross with the component; on the high side they are harder to "
        "patch. Severity comes from the scanner's data; CISA KEV entries are marked kev=true.",
        remediation="Upgrade to the fixed version, or record why the vulnerability does not apply.",
    ),
)

BASICS = (
    _rule(
        "secret.detected",
        "Content contains what looks like a credential",
        H,
        ("IA-5",),
        "Credentials that cross the gap are credentials exposed to everyone on both sides, and "
        "point at services the high side should not reach.",
        remediation="Remove the credential, revoke it, and load secrets at run time instead.",
    ),
    _rule(
        "document.active-content",
        "Document contains macros, scripts or embedded objects",
        M,
        ("SI-3",),
        "Macros, PDF JavaScript and launch actions, OLE objects and remote templates run code "
        "or fetch content when a document is opened.",
    ),
)

SCANNER_RULES = (*PLUGINS, *BASICS)
