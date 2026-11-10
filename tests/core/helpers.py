"""Shared test data for core tests."""

from airlock.core.model import Severity, ToolRef
from airlock.core.rules import RuleSpec

TOOL = ToolRef("airlock-test", "0")
KEY_ID = "ed25519:" + "0123456789abcdef" * 4

RULES = (
    RuleSpec(
        "model.pickle.dangerous-import",
        "1",
        "Pickle imports a dangerous callable",
        Severity.CRITICAL,
        ("SI-3", "SR-10"),
        "Unpickling runs arbitrary code.",
    ),
    RuleSpec(
        "container.user.root",
        "1",
        "Container runs as root",
        Severity.MEDIUM,
        ("CM-7",),
        "Least functionality.",
    ),
    RuleSpec(
        "offline.telemetry.enabled",
        "1",
        "Telemetry enabled",
        Severity.HIGH,
        ("SC-7",),
        "Egress path.",
    ),
    RuleSpec(
        "malware.scan.detected",
        "1",
        "Malware detected",
        Severity.CRITICAL,
        ("SI-3",),
        "Malicious code.",
    ),
    RuleSpec(
        "document.metadata.author",
        "1",
        "Document metadata names an author",
        Severity.LOW,
        ("CM-8",),
        "Metadata leakage.",
    ),
    RuleSpec(
        "vuln.component.known",
        "1",
        "Component has a known vulnerability",
        Severity.HIGH,
        ("RA-5",),
        "Known vulnerabilities.",
    ),
    RuleSpec(
        "integrity.hash.mismatch",
        "1",
        "Content does not match the manifest",
        Severity.CRITICAL,
        ("SI-7", "SI-7(1)"),
        "Tampering.",
        final=True,
    ),
)
