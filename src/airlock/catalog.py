"""Built-in rules: every check airlock can report, with severity and control mapping.

Two classes of rule, with different rules of engagement:

* **Integrity and authenticity** (``final=True``): hash mismatch, bad or missing signature,
  replay, wrong enclave, broken custody or ledger. A failure is always ``block``. No policy
  setting, waiver or approval can change that; if it could, the airlock would not be a control.
* **Everything else** is judged by policy. Where policy decides ``block`` (a pickle model, remote
  code, a licence, an unapproved package, a path-traversal archive), the blocker can be
  overridden for one bundle by a quorum of approvers with a written justification, recorded as
  signed evidence.
"""

from airlock.catalog_data import DATA_RULES
from airlock.catalog_models import MODEL_RULES
from airlock.catalog_offline import OFFLINE_RULES
from airlock.catalog_scanners import SCANNER_RULES
from airlock.catalog_software import SOFTWARE_RULES
from airlock.core.controls import ControlCatalog
from airlock.core.model import Severity
from airlock.core.rules import RuleRegistry, RuleSpec

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


INTEGRITY = (
    _rule(
        "integrity.bundle.malformed",
        "Bundle control file is missing or unreadable",
        C,
        ("SI-7",),
        "Without its signed statement and manifest a bundle cannot be verified at all.",
        final=True,
    ),
    _rule(
        "integrity.signature.invalid",
        "Bundle signature does not verify",
        C,
        ("SI-7", "AU-10"),
        "The signed statement was altered, or was not signed by the key it names.",
        final=True,
    ),
    _rule(
        "integrity.signature.untrusted-key",
        "Bundle is not signed by a key this side trusts",
        C,
        ("SI-7", "AU-10", "SR-4"),
        "Only keys pinned in the receiving side's policy, valid today and allowed to pack for "
        "the bundle's source, establish where a bundle came from.",
        final=True,
    ),
    _rule(
        "integrity.statement.subject-mismatch",
        "Control file does not match the signed statement",
        C,
        ("SI-7",),
        "The manifest, analysis, assessment or request was changed after signing.",
        final=True,
    ),
    _rule(
        "integrity.hash.mismatch",
        "Content does not match the manifest",
        C,
        ("SI-7",),
        "The file was modified or corrupted between pack and import.",
        final=True,
    ),
    _rule(
        "integrity.entry.missing",
        "Manifest entry is missing from the payload",
        C,
        ("SI-7", "CM-8"),
        "An incomplete delivery tempts people to carry the missing piece across informally.",
        final=True,
    ),
    _rule(
        "integrity.entry.unexpected",
        "Payload contains content that is not in the manifest",
        C,
        ("SI-7", "CM-8"),
        "Content added after signing has not been inventoried, inspected or approved.",
        final=True,
    ),
    _rule(
        "integrity.custody.broken",
        "Chain-of-custody log is missing, broken or not signed by trusted keys",
        C,
        ("AU-10", "MP-5"),
        "The custody log must chain from a signed 'packed' event for this exact manifest.",
        final=True,
    ),
    _rule(
        "integrity.ledger.broken",
        "Receiving-side ledger is broken",
        C,
        ("AU-10", "SI-7"),
        "Replay, downgrade and delta checks all depend on the ledger of accepted bundles.",
        final=True,
    ),
)

TRANSFER = (
    _rule(
        "transfer.destination.mismatch",
        "Bundle is addressed to a different enclave",
        C,
        ("AC-4", "SC-7"),
        "A bundle approved for one destination must not be imported into another.",
        final=True,
    ),
    _rule(
        "transfer.destination.unbound",
        "Bundle does not name a destination",
        H,
        ("AC-4",),
        "Without a transfer request the bundle is not bound to any enclave and could be "
        "imported anywhere.",
        final=True,
    ),
    _rule(
        "transfer.source.unaccepted",
        "Bundle comes from a source this enclave does not accept",
        H,
        ("AC-4", "SC-7", "SR-3"),
        "The receiving policy lists the networks it accepts transfers from.",
        final=True,
    ),
    _rule(
        "replay.bundle.expired",
        "Bundle is older than the policy allows",
        H,
        ("SI-7", "SI-2"),
        "An old bundle may reintroduce superseded, vulnerable content.",
        final=True,
    ),
    _rule(
        "replay.bundle.already-accepted",
        "A bundle with this id and signed statement was already accepted",
        H,
        ("SI-7", "CM-3"),
        "Re-importing an accepted bundle is either a mistake or a replay. The signed statement "
        "matches the earlier import; whether the content still matches it is the integrity "
        "rules' finding.",
        final=True,
    ),
    _rule(
        "replay.bundle.id-reused",
        "A different bundle reuses the id of one already accepted",
        C,
        ("SI-7", "CM-3"),
        "The signed statement differs from the one accepted under this bundle id: another bundle "
        "is passing itself off as one already imported.",
        final=True,
    ),
    _rule(
        "replay.bundle.out-of-order",
        "A newer bundle from the same source and stream was already accepted",
        H,
        ("SI-7", "CM-3"),
        "Importing an older bundle after a newer one can roll content back.",
        final=True,
    ),
    _rule(
        "replay.clock.regression",
        "System clock is earlier than the last ledger entry",
        H,
        ("AU-10",),
        "Age, expiry and ordering checks are meaningless if the clock has gone backwards.",
        remediation="Correct the system clock. If the earlier ledger times were the ones that "
        "were wrong, record the correction with 'airlock ledger adjust-clock'.",
        final=True,
    ),
    _rule(
        "replay.clock.skew",
        "Bundle was created later than this system's clock allows",
        L,
        ("AU-10",),
        "Either this system's clock is behind or the packing side's is ahead. Clocks drift on "
        "disconnected systems; correct it before it becomes a regression.",
    ),
    _rule(
        "replay.clock.adjusted",
        "The clock was deliberately adjusted since the previous import",
        I,
        ("AU-10", "CM-3"),
        "A signed clock adjustment was recorded in the ledger. It is listed here so the "
        "adjustment and its reason appear in the evidence for the next import.",
    ),
    _rule(
        "delta.base.unknown",
        "Delta bundle builds on a snapshot this side never accepted",
        C,
        ("SI-7", "CM-3"),
        "A delta is only meaningful on top of the exact snapshot it was computed against.",
        final=True,
    ),
    _rule(
        "trust.signer.unpinned",
        "Signing key was supplied on the command line, not pinned in policy",
        L,
        ("SR-4", "CM-6"),
        "Keys should be pinned, with holder, role and validity, in the receiving side's policy.",
    ),
    _rule(
        "policy.digest.changed",
        "Policy differs from the one used for the previous import",
        I,
        ("CM-3",),
        "Policy and key changes are logged so that every rotation is an explicit event.",
    ),
    _rule(
        "policy.waiver.expired",
        "Policy contains an expired waiver",
        L,
        ("CM-3",),
        "Expired waivers no longer apply and should be renewed or removed.",
    ),
    _rule(
        "plugin.required.missing",
        "A scanner the policy requires is not available",
        H,
        ("SI-3", "RA-5"),
        "Policy marks this scanner as required for import.",
    ),
)

REQUEST = (
    _rule(
        "request.artifact.undeclared",
        "Content is not declared in the transfer request",
        M,
        ("CM-3", "CM-8"),
        "Everything that crosses must be something the approvers agreed to move.",
    ),
    _rule(
        "request.content.missing",
        "Content declared in the transfer request is absent",
        H,
        ("CM-3", "CM-8"),
        "An incomplete delivery will not work, and invites informal workarounds.",
    ),
)

PATHS = (
    _rule(
        "path.name.unsafe",
        "File name cannot be represented safely",
        H,
        ("SI-7", "CM-8"),
        "Names with backslashes, control characters, undecodable bytes or non-NFC Unicode do "
        "not survive every filesystem unchanged, so the content cannot be tracked reliably.",
        final=True,
        remediation="Rename the file before packing.",
    ),
    _rule(
        "path.case-collision",
        "Paths differ only by case",
        H,
        ("SI-7",),
        "On a case-insensitive target one file silently overwrites the other.",
    ),
    _rule(
        "path.length.exceeded",
        "Path is longer than the policy allows",
        M,
        ("CM-6",),
        "Over-long paths fail on some targets.",
    ),
    _rule(
        "path.link.symlink",
        "Symbolic link was recorded but not followed",
        L,
        ("CM-8",),
        "Links are never followed or recreated; their target is not part of the delivery.",
    ),
    _rule(
        "path.link.escapes",
        "Symbolic link points outside the delivery",
        H,
        ("AC-4", "CM-8"),
        "The link depends on, and reveals, a path on the source host.",
    ),
    _rule(
        "path.special-file",
        "Device, FIFO or socket",
        H,
        ("CM-7",),
        "Special files have no place in a delivery and cannot be transferred.",
    ),
    _rule(
        "size.artifact.exceeded",
        "File is larger than the policy allows",
        M,
        ("CM-6",),
        "Oversized content needs an explicit decision.",
    ),
    _rule(
        "inventory.artifact.unclassified",
        "Content type was not recognised",
        I,
        ("CM-8",),
        "The file is inventoried, hashed and signed, but no type-specific checks ran on it.",
    ),
    _rule(
        "inventory.handler.error",
        "A handler failed while inspecting content",
        M,
        ("SR-10",),
        "Type-specific checks did not complete for this content.",
    ),
)

ARCHIVE = (
    _rule(
        "archive.member.path-traversal",
        "Archive member would be written outside the extraction directory",
        H,
        ("SI-3", "SI-7"),
        "Absolute paths and '..' segments overwrite files when the archive is extracted.",
    ),
    _rule(
        "archive.member.unsafe-name",
        "Archive member name cannot be represented safely",
        M,
        ("SI-7",),
        "Different tools will extract this member under different names.",
    ),
    _rule(
        "archive.member.link-escape",
        "Archive link points outside the archive",
        H,
        ("SI-3", "SI-7"),
        "Extracting through such a link writes or reads outside the extraction directory.",
    ),
    _rule(
        "archive.member.special-file",
        "Archive contains a device, FIFO or socket",
        H,
        ("CM-7",),
        "Special files in an archive are almost never legitimate.",
    ),
    _rule(
        "archive.member.setuid",
        "Archive member has the setuid or setgid bit",
        M,
        ("CM-7", "AC-4"),
        "Privileged executables should be deliberate and reviewed.",
    ),
    _rule(
        "archive.member.encrypted",
        "Archive member is encrypted",
        M,
        ("SR-10", "SI-3"),
        "Encrypted content cannot be inspected.",
    ),
    _rule(
        "archive.member.duplicate",
        "Archive contains the same member name more than once",
        M,
        ("SI-7", "SI-3"),
        "Tools disagree on which copy wins, so what is inspected may not be what is used.",
    ),
    _rule(
        "archive.format.unreadable",
        "Archive is corrupt or uses an unsupported feature",
        M,
        ("SR-10",),
        "Its contents could not be inspected.",
    ),
    _rule(
        "archive.limit.ratio",
        "Archive expands far beyond its size (possible decompression bomb)",
        H,
        ("SI-3", "SC-7"),
        "Inspection stopped at the policy's expansion ratio.",
    ),
    _rule(
        "archive.limit.expanded-size",
        "Archive expands beyond the policy's size limit",
        H,
        ("SI-3",),
        "Inspection stopped at the policy's expanded-size limit.",
    ),
    _rule(
        "archive.limit.members",
        "Archive has more members than the policy allows",
        H,
        ("SI-3",),
        "Inspection stopped at the policy's member limit.",
    ),
    _rule(
        "archive.limit.depth",
        "Archives are nested deeper than the policy allows",
        M,
        ("SR-10", "SI-3"),
        "Archives beyond the nesting limit were not opened.",
    ),
)

# Checks on archive members; reported "not assessed" for any archive that could not be opened.
ARCHIVE_MEMBER_RULES = tuple(r.id for r in ARCHIVE if r.id.startswith("archive.member."))

ALL = (
    *INTEGRITY,
    *TRANSFER,
    *REQUEST,
    *PATHS,
    *ARCHIVE,
    *MODEL_RULES,
    *SOFTWARE_RULES,
    *SCANNER_RULES,
    *DATA_RULES,
    *OFFLINE_RULES,
)


def builtin_registry(catalog: ControlCatalog | None = None) -> RuleRegistry:
    registry = RuleRegistry(catalog or ControlCatalog.builtin())
    registry.register(*ALL)
    return registry
