"""Core data models shared by every module (see docs/design/17-core-models.md).

All models are frozen dataclasses. Serialisation goes through ``superscrubber104.core.serde``
and every document that is hashed or signed is encoded with
``superscrubber104.core.canonical``.

Two layers are kept apart on purpose:

* **Integrity** (``Manifest``/``Entry``): paths, sizes and hashes. Independent of tool version and
  policy, so its digest identifies the content and nothing else. This is what gets signed.
* **Interpretation** (``Analysis``/``Artifact``/``Unit``): what the content *is*. Derived, depends
  on the tool version, and is regenerated on the high side rather than trusted.
"""

import re
from collections import Counter
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from superscrubber104.core.canonical import JSON, digest
from superscrubber104.core.paths import validate_bundle_path

API_VERSION = "superscrubber104/v1alpha1"
UNCLASSIFIED = "unclassified"

DIGEST = re.compile(r"^(sha256|sha384|sha512):[0-9a-f]{64,128}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _require_kind(obj: object, expected: str) -> None:
    api_version = getattr(obj, "api_version")  # noqa: B009
    kind = getattr(obj, "kind")  # noqa: B009
    if api_version != API_VERSION:
        raise ValueError(f"unsupported apiVersion {api_version!r}; expected {API_VERSION!r}")
    if kind != expected:
        raise ValueError(f"kind must be {expected!r}, got {kind!r}")


def _require_digest(value: str | None, name: str) -> None:
    if value is not None and not DIGEST.match(value):
        raise ValueError(f"{name} must be '<algorithm>:<hex>', got {value!r}")


def _check_hashes(hashes: Mapping[str, str], where: object) -> None:
    for algorithm, value in hashes.items():
        if not _HEX.match(value):
            raise ValueError(f"{where}: {algorithm} must be lowercase hex")
    if "sha256" in hashes and not _SHA256_HEX.match(hashes["sha256"]):
        raise ValueError(f"{where}: sha256 must be 64 lowercase hex characters")


# --- Enumerations -------------------------------------------------------------------------------


class Severity(StrEnum):
    """How bad a FAIL is. Set by the rule, not by policy."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {s: i for i, s in enumerate(reversed(list(Severity)))}


class Result(StrEnum):
    """What a check observed."""

    PASS = "pass"  # noqa: S105 - check ran, condition not present
    FAIL = "fail"  # check ran, condition present
    NOT_ASSESSED = "not-assessed"  # check could not run
    ERROR = "error"  # check crashed or got malformed input


class Disposition(StrEnum):
    """What policy decides to do about a finding. Ordered from least to most restrictive."""

    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_APPROVAL = "require-approval"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _DISPOSITION_RANK[self]


_DISPOSITION_RANK = {d: i for i, d in enumerate(Disposition)}


class Verdict(StrEnum):
    PASSED = "passed"
    NEEDS_APPROVAL = "needs-approval"  # approvals outstanding on require-approval findings
    BLOCKED = "blocked"  # a policy blocker stands; it can be overridden by an approval quorum
    REFUSED = "refused"  # integrity/authenticity failed, or a non-overridable policy block


class Stage(StrEnum):
    PACK = "pack"
    VERIFY = "verify"
    OFFLINE_CHECK = "offline-check"
    INSPECT = "inspect"
    STAGE = "stage"
    EVAL = "eval"
    PATCH = "patch"
    AGENT_SCAN = "agent-scan"  # phase 2
    GATEWAY = "gateway"  # phase 3


class EntryType(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    OTHER = "other"  # devices, FIFOs, sockets: always a finding


class UnitKind(StrEnum):
    MODEL_PACKAGE = "model-package"
    RUNTIME_PROFILE = "runtime-profile"
    PYTHON_ENVIRONMENT = "python-environment"
    NODE_ENVIRONMENT = "node-environment"
    JVM_ENVIRONMENT = "jvm-environment"
    GO_ENVIRONMENT = "go-environment"
    RUST_ENVIRONMENT = "rust-environment"
    DOTNET_ENVIRONMENT = "dotnet-environment"
    TERRAFORM_ENVIRONMENT = "terraform-environment"
    REPO_MIRROR = "repo-mirror"
    CONTAINER_IMAGE = "container-image"
    VM_IMAGE = "vm-image"
    PATCH_SET = "patch-set"
    KNOWLEDGE_BASE = "knowledge-base"
    DATASET = "dataset"
    ZARF_PACKAGE = "zarf-package"
    HAULER_HAUL = "hauler-haul"


class ComponentType(StrEnum):
    """CycloneDX 1.6 component types."""

    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    CONTAINER = "container"
    PLATFORM = "platform"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    DEVICE_DRIVER = "device-driver"
    FIRMWARE = "firmware"
    FILE = "file"
    MACHINE_LEARNING_MODEL = "machine-learning-model"
    DATA = "data"
    CRYPTOGRAPHIC_ASSET = "cryptographic-asset"


class SubjectKind(StrEnum):
    ARTIFACT = "artifact"
    UNIT = "unit"
    COMPONENT = "component"
    BUNDLE = "bundle"
    REQUEST = "request"
    POLICY = "policy"
    HOST = "host"  # phase 2: a workstation or repository being scanned
    TOOL_CALL = "tool-call"  # phase 3: one MCP call seen by the gateway


class TrustLevel(StrEnum):
    """How strongly upstream genuineness was established. Ordered weakest to strongest."""

    NONE = "none"
    ASSERTED = "asserted"  # a low-side claim, e.g. a repository revision
    CHECKSUM = "checksum"  # matches a checksum list that is itself unauthenticated
    PINNED_CHECKSUM = "pinned-checksum"  # matches a digest pinned in the verifier's own policy
    SIGNATURE = "signature"  # signature verified against a key pinned in policy

    @property
    def rank(self) -> int:
        return _TRUST_RANK[self]


_TRUST_RANK = {t: i for i, t in enumerate(TrustLevel)}


# --- Identity -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolRef:
    """The tool that produced a result: a superscrubber104 handler, or a plugin and its data
    versions."""

    name: str
    version: str
    extra: Mapping[str, str] | None = None  # e.g. {"dbVersion": "27412"}


@dataclass(frozen=True, slots=True, order=True)
class ArtifactRef:
    """Location of an artifact: a path, plus the path inside nested archives if any.

    ``unsafe`` marks a reference whose last part is a hostile or unrepresentable name
    (``../../etc/passwd``, a backslash, undecodable bytes) recorded in escaped form. Such a
    reference can be inventoried and reported on, but is never turned into a filesystem path.

    ``ArtifactRef(".")`` (``BUNDLE_ROOT``) stands for the top of the delivery. It is only used as
    a unit root, for a model package that is the delivery itself.
    """

    path: str
    member: tuple[str, ...] = ()
    unsafe: bool = False

    def __post_init__(self) -> None:
        parts = (self.path, *self.member)
        if self.unsafe:
            if not all(parts) or any("\x00" in p for p in parts):
                raise ValueError("unsafe references still need non-empty, NUL-free parts")
            return
        if self.path == "." and not self.member:
            return
        for part in parts:
            validate_bundle_path(part)

    @property
    def display(self) -> str:
        """Human form, e.g. ``images/app.tar!/layer.tar!/usr/bin/x``. Not parsed back."""
        return "!/".join((self.path, *self.member))

    @property
    def nested(self) -> bool:
        return bool(self.member)

    def child(self, name: str, *, unsafe: bool = False) -> "ArtifactRef":
        return ArtifactRef(self.path, (*self.member, name), unsafe=self.unsafe or unsafe)

    def __str__(self) -> str:
        return self.display


# --- Integrity layer ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Entry:
    """One payload entry: the facts that integrity verification checks, and nothing else.

    File modes are deliberately absent: removable media and Windows hosts do not preserve them,
    so they cannot be verified after transfer. Modes inside archives are covered by the archive's
    own hash and are recorded in the analysis.
    """

    path: str
    entry_type: EntryType
    size: int = 0
    hashes: Mapping[str, str] = field(default_factory=dict)
    chunks: tuple[str, ...] = ()  # sha256 per ``Manifest.chunk_size`` block; empty if one block
    link_target: str | None = None  # symlinks are recorded, never followed or recreated
    carried: bool = False  # delta bundles: content is unchanged from ``Manifest.base``

    def __post_init__(self) -> None:
        validate_bundle_path(self.path)
        if self.size < 0:
            raise ValueError(f"{self.path}: size must be non-negative")
        if self.entry_type is EntryType.FILE and "sha256" not in self.hashes:
            raise ValueError(f"{self.path}: files must have a sha256 hash")
        _check_hashes(self.hashes, self.path)
        if any(not _SHA256_HEX.match(c) for c in self.chunks):
            raise ValueError(f"{self.path}: chunk hashes must be sha256 hex")
        if (self.link_target is not None) != (self.entry_type in _LINK_TYPES):
            raise ValueError(f"{self.path}: link_target is set if and only if this is a link")

    @property
    def sha256(self) -> str | None:
        return self.hashes.get("sha256")


_LINK_TYPES = frozenset({EntryType.SYMLINK, EntryType.HARDLINK})


@dataclass(frozen=True, slots=True)
class Manifest:
    """Deterministic inventory of the full delivery state.

    No timestamps, host details, policy or tool versions: the same content always yields the same
    bytes, so the digest is the identity of a snapshot. For a delta bundle the manifest still lists
    every entry; those marked ``carried`` come from the accepted snapshot named by ``base``.
    """

    entries: tuple[Entry, ...]
    chunk_size: int
    base: str | None = None
    extensions: Mapping[str, JSON] = field(default_factory=dict)
    api_version: str = API_VERSION
    kind: str = "Manifest"

    def __post_init__(self) -> None:
        _require_kind(self, "Manifest")
        _require_digest(self.base, "base")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        paths = [e.path for e in self.entries]
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            raise ValueError("entries must be unique and sorted by path; use Manifest.create")
        if self.base is None and any(e.carried for e in self.entries):
            raise ValueError("carried entries require a base manifest")

    @classmethod
    def create(
        cls, entries: Iterable[Entry], *, chunk_size: int, base: str | None = None
    ) -> "Manifest":
        """Build a manifest with entries in canonical order."""
        ordered = tuple(sorted(entries, key=lambda e: e.path))
        return cls(entries=ordered, chunk_size=chunk_size, base=base)


@dataclass(frozen=True, slots=True)
class Provenance:
    """Predicate of the signed statement: who packed what, when, for whom.

    This is what binds a manifest to one transfer. Replay, cross-enclave reuse and stale bundles
    are detected from these fields, not from the manifest.
    """

    bundle_id: str
    created_at: datetime
    tool: ToolRef
    policy_digest: str  # the packing side's policy; informational on the receiving side
    source: str | None = None
    destination: str | None = None
    stream: str = "default"  # ordering scope for recurring transfers (e.g. "patches-alma9")
    profile: str = "routine"
    request_id: str | None = None
    extensions: Mapping[str, JSON] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_digest(self.policy_digest, "policy_digest")


@dataclass(frozen=True, slots=True)
class BundleDescriptor:
    """``superscrubber104-bundle.json``: marks a directory as a bundle. A pointer only; never
    trusted."""

    layout_version: int = 1
    statement: str = "statement.dsse.json"
    api_version: str = API_VERSION
    kind: str = "Bundle"

    def __post_init__(self) -> None:
        _require_kind(self, "Bundle")


# --- Interpretation layer -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Verification:
    """Outcome of checking one upstream signature or checksum for an artifact or component."""

    type: str  # "gpg", "authenticode", "sigstore", "checksum", "glance", ...
    level: TrustLevel
    result: Result
    signer: str | None = None  # fingerprint or subject of the upstream signer
    anchor: str | None = None  # name of the policy ``trust.upstream`` entry that was used
    detail: Mapping[str, JSON] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Artifact:
    """What one file, link or archive member was found to be."""

    ref: ArtifactRef
    entry_type: EntryType
    size: int = 0
    kinds: tuple[str, ...] = (UNCLASSIFIED,)  # most confident first; polyglots have several
    hashes: Mapping[str, str] = field(default_factory=dict)
    link_target: str | None = None
    mode: int | None = None  # permission bits, where the container format records them
    media_type: str | None = None  # detected from content, not the extension
    handlers: tuple[ToolRef, ...] = ()
    metadata: Mapping[str, JSON] = field(default_factory=dict)
    verifications: tuple[Verification, ...] = ()

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError(f"{self.ref}: size must be non-negative")
        if not self.kinds:
            raise ValueError(f"{self.ref}: at least one kind is required")
        _check_hashes(self.hashes, self.ref)

    @property
    def kind(self) -> str:
        return self.kinds[0]

    @property
    def sha256(self) -> str | None:
        return self.hashes.get("sha256")


@dataclass(frozen=True, slots=True)
class LicenseRef:
    """Either an SPDX expression or a named licence that has no SPDX id (e.g. a model licence)."""

    expression: str | None = None  # "Apache-2.0", "MIT OR Apache-2.0", "LicenseRef-llama3.1"
    name: str | None = None  # "Llama 3.1 Community License"

    def __post_init__(self) -> None:
        if not (self.expression or self.name):
            raise ValueError("a licence needs an SPDX expression or a name")


@dataclass(frozen=True, slots=True)
class UpstreamRef:
    """Where something came from, precisely enough to fetch the identical bytes again.

    On its own this is a claim made by the packing side. ``Verification`` records what was
    actually checked.
    """

    type: str  # "huggingface", "ollama", "oci", "pypi", "npm", "url", ...
    reference: str  # "example-org/tiny-chat", "registry.example/app", a URL
    revision: str | None = None  # commit SHA, tag, version
    digest: str | None = None  # manifest or content digest published upstream


@dataclass(frozen=True, slots=True)
class Component:
    """An identifiable software or AI component; maps one-to-one onto a CycloneDX component."""

    bom_ref: str
    type: ComponentType
    name: str
    version: str | None = None
    purl: str | None = None
    licenses: tuple[LicenseRef, ...] = ()
    supplier: str | None = None
    hashes: Mapping[str, str] = field(default_factory=dict)
    upstream: UpstreamRef | None = None
    evidence: tuple[ArtifactRef, ...] = ()  # every place this component occurs
    children: tuple[str, ...] = ()  # bom_refs nested inside this component
    depends_on: tuple[str, ...] = ()  # bom_refs this component needs
    verifications: tuple[Verification, ...] = ()
    properties: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UnitMember:
    role: str  # "weights-shard", "tokenizer", "chat-template", "lockfile", "wheel", ...
    artifact: ArtifactRef
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class Requirement:
    """Something a unit needs that is not one of its own members.

    Examples: an adapter's base model, a knowledge base's embedding model, the runtime a model
    was tested on. ``satisfied_by`` is a unit id in this bundle, ``"high-side:<reference>"`` when
    a high-side inventory supplies it, or None when nothing does (a completeness finding).
    """

    relation: str  # "base-model", "embedding-model", "runtime", "image", ...
    name: str
    kind: UnitKind | None = None
    digest: str | None = None  # expected unit digest or upstream content digest
    version: str | None = None
    satisfied_by: str | None = None


@dataclass(frozen=True, slots=True)
class UnitClaim:
    """A handler's claim that an artifact belongs to a unit; assemblers build units from these."""

    kind: UnitKind
    root: ArtifactRef
    role: str
    artifact: ArtifactRef
    sha256: str | None = None
    facts: Mapping[str, JSON] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Unit:
    """A typed group of artifacts that only works as a whole."""

    kind: UnitKind
    name: str
    root: ArtifactRef  # directory, file or archive member anchoring the unit; unique per kind
    members: tuple[UnitMember, ...] = ()
    requires: tuple[Requirement, ...] = ()
    components: tuple[str, ...] = ()  # bom_refs
    attributes: Mapping[str, JSON] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.kind.value}:{self.root.display}"

    @property
    def digest(self) -> str:
        """Content identity: kind plus the sorted (role, sha256) of every member.

        Independent of where the unit sits, so it can pin a unit in an allowlist or waiver, link
        an adapter to its base model, and compare a unit across bundles.
        """
        pairs = sorted((m.role, m.sha256 or "") for m in self.members)
        members: list[JSON] = [[role, sha256] for role, sha256 in pairs]
        return digest([self.kind.value, members])


@dataclass(frozen=True, slots=True)
class Analysis:
    """Interpretation of a bundle by one tool version. Regenerated, never trusted, on import."""

    tool: ToolRef
    artifacts: tuple[Artifact, ...] = ()
    units: tuple[Unit, ...] = ()
    components: tuple[Component, ...] = ()
    api_version: str = API_VERSION
    kind: str = "Analysis"

    def __post_init__(self) -> None:
        _require_kind(self, "Analysis")

    @classmethod
    def create(
        cls,
        tool: ToolRef,
        artifacts: Iterable[Artifact],
        units: Iterable[Unit] = (),
        components: Iterable[Component] = (),
    ) -> "Analysis":
        return cls(
            tool=tool,
            artifacts=tuple(sorted(artifacts, key=lambda a: a.ref)),
            units=tuple(sorted(units, key=lambda u: u.id)),
            components=tuple(sorted(components, key=lambda c: c.bom_ref)),
        )


# --- Findings and assessments -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Subject:
    """What a finding is about, optionally narrowed to a place inside it."""

    kind: SubjectKind
    artifact: ArtifactRef | None = None
    unit: str | None = None  # unit id, "<kind>:<root>"
    component: str | None = None  # bom_ref
    name: str | None = None  # host or tool-call subjects (phases 2 and 3)
    locator: str | None = None  # line, byte offset, JSON pointer, tool name, ...

    def __post_init__(self) -> None:
        for attr, kind in (
            ("artifact", SubjectKind.ARTIFACT),
            ("unit", SubjectKind.UNIT),
            ("component", SubjectKind.COMPONENT),
        ):
            if (getattr(self, attr) is not None) != (self.kind is kind):
                raise ValueError(f"{attr} is set if and only if kind is {kind.value!r}")

    @classmethod
    def of_artifact(cls, ref: ArtifactRef, locator: str | None = None) -> "Subject":
        return cls(SubjectKind.ARTIFACT, artifact=ref, locator=locator)

    @classmethod
    def of_path(cls, path: str) -> "Subject":
        return cls(SubjectKind.ARTIFACT, artifact=ArtifactRef(path))

    @classmethod
    def of_unit(cls, unit: Unit) -> "Subject":
        return cls(SubjectKind.UNIT, unit=unit.id)

    @classmethod
    def of_component(cls, bom_ref: str) -> "Subject":
        return cls(SubjectKind.COMPONENT, component=bom_ref)

    @classmethod
    def bundle(cls) -> "Subject":
        return cls(SubjectKind.BUNDLE)

    @classmethod
    def request(cls) -> "Subject":
        return cls(SubjectKind.REQUEST)

    @classmethod
    def policy(cls) -> "Subject":
        return cls(SubjectKind.POLICY)

    @property
    def display(self) -> str:
        """Stable text form; policy waivers match against it."""
        if self.artifact is not None:
            base = self.artifact.display
        else:
            base = self.unit or self.component or self.name or self.kind.value
        return f"{base}#{self.locator}" if self.locator else base

    @property
    def path(self) -> str | None:
        """Path used for policy path scoping: the artifact path, or the unit root."""
        if self.artifact is not None:
            return self.artifact.display
        if self.unit is not None:
            return self.unit.split(":", 1)[1]
        return None


@dataclass(frozen=True, slots=True)
class Finding:
    """The result of one check on one subject. Created only through the rule registry."""

    id: str
    rule: str
    rule_version: str
    result: Result
    severity: Severity
    subject: Subject
    title: str
    controls: tuple[str, ...]
    tool: ToolRef
    detail: Mapping[str, JSON] = field(default_factory=dict)
    attributes: Mapping[str, str] = field(default_factory=dict)  # facets policy can select on
    not_assessed_reason: str | None = None

    def __post_init__(self) -> None:
        if (self.not_assessed_reason is not None) != (self.result is Result.NOT_ASSESSED):
            raise ValueError("not_assessed_reason is set if and only if result is not-assessed")


@dataclass(frozen=True, slots=True)
class Decision:
    """The policy engine's decision on one finding, traceable to one policy entry."""

    finding: str  # finding id
    disposition: Disposition
    matched: str  # "rules[4]", "waivers[1]", "defaults.severity.high", "final", "pass"
    # Distinct approvers needed to clear a require-approval finding or to override a blocker.
    approvals_required: int = 0
    waiver: str | None = None
    # True when nothing can clear it: an integrity or authenticity rule failed, or the policy
    # marks the rule as not overridable.
    final: bool = False

    @property
    def clearable(self) -> bool:
        """Whether signed approvals can clear this decision."""
        gated = self.disposition in (Disposition.REQUIRE_APPROVAL, Disposition.BLOCK)
        return gated and not self.final


@dataclass(frozen=True, slots=True)
class Approval:
    """A signed, per-bundle clearance of one finding: an approval, or the override of a blocker.

    Carried as the data of an ``approved`` custody event; the event's signature identifies the
    approver. Bound to the manifest and to the exact finding (by digest), so it lapses if either
    the content or what was found changes. The written justification is part of what is signed.
    """

    manifest_digest: str
    finding: str  # finding id
    finding_digest: str
    justification: str

    def __post_init__(self) -> None:
        if not self.justification.strip():
            raise ValueError("an approval needs a written justification")


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """What the verifier made of one approval in the custody log. Kept as evidence either way."""

    finding: str  # finding id
    key_id: str | None
    holder: str | None
    justification: str
    counted: bool
    reason: str | None = None  # why it was not counted


@dataclass(frozen=True, slots=True)
class Coverage:
    """What one rule did during an assessment. Present for every registered rule, so a rule
    that never ran is visible as such rather than silently absent."""

    rule: str
    rule_version: str
    controls: tuple[str, ...]
    passed: int = 0
    failed: int = 0
    not_assessed: int = 0
    errors: int = 0

    @property
    def exercised(self) -> bool:
        return bool(self.passed or self.failed or self.not_assessed or self.errors)


@dataclass(frozen=True, slots=True)
class PluginStatus:
    name: str
    present: bool
    version: str | None = None
    binary_sha256: str | None = None
    pinned: bool | None = None  # None: policy does not pin this plugin
    data_version: str | None = None  # e.g. signature database version
    data_age_seconds: int | None = None
    reason: str | None = None  # why absent / not used


@dataclass(frozen=True, slots=True)
class Summary:
    results: Mapping[Result, int]
    dispositions: Mapping[Disposition, int]
    verdict: Verdict


def summarize(
    findings: Iterable[Finding], decisions: Iterable[Decision], approved: Collection[str] = ()
) -> Summary:
    """Counts and overall verdict.

    ``approved`` holds ids of findings whose approval quorum is met. Approvals clear
    require-approval findings and override policy blockers; they never clear a final decision.
    """
    decisions = list(decisions)
    results = Counter(f.result for f in findings)
    dispositions = Counter(d.disposition for d in decisions)
    standing = {d.disposition for d in decisions if d.clearable and d.finding not in approved}
    if any(d.final and d.disposition is Disposition.BLOCK for d in decisions):
        verdict = Verdict.REFUSED
    elif Disposition.BLOCK in standing:
        verdict = Verdict.BLOCKED
    elif Disposition.REQUIRE_APPROVAL in standing:
        verdict = Verdict.NEEDS_APPROVAL
    else:
        verdict = Verdict.PASSED
    return Summary(
        results={r: results[r] for r in Result},
        dispositions={d: dispositions[d] for d in Disposition},
        verdict=verdict,
    )


@dataclass(frozen=True, slots=True)
class Assessment:
    """One run of pack, verify or a standalone check. Holds the only timestamps besides logs."""

    tool: ToolRef
    stage: Stage
    started_at: datetime
    finished_at: datetime
    policy_digest: str
    summary: Summary
    manifest_digest: str | None = None
    plugins: tuple[PluginStatus, ...] = ()
    coverage: tuple[Coverage, ...] = ()
    findings: tuple[Finding, ...] = ()
    decisions: tuple[Decision, ...] = ()
    approvals: tuple[ApprovalRecord, ...] = ()
    api_version: str = API_VERSION
    kind: str = "Assessment"

    def __post_init__(self) -> None:
        _require_kind(self, "Assessment")
        _require_digest(self.policy_digest, "policy_digest")
        _require_digest(self.manifest_digest, "manifest_digest")
        finding_ids = [f.id for f in self.findings]
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("duplicate finding ids")
        if sorted(d.finding for d in self.decisions) != sorted(finding_ids):
            raise ValueError("every finding needs exactly one decision")

    @property
    def refused(self) -> bool:
        return self.summary.verdict is Verdict.REFUSED


@dataclass(frozen=True, slots=True)
class Receipt:
    """Signed import record made on the receiving side; one per verification, whatever the verdict.

    Identifiers, digests, a verdict and a time only: no free text, so it is safe to send back
    outbound. Receipts form the receiving side's ledger of what it has accepted.
    """

    bundle_id: str
    manifest_digest: str
    statement_digest: str
    assessment_digest: str
    policy_digest: str
    verdict: Verdict
    verified_at: datetime
    bundle_created_at: datetime
    enclave: str | None = None
    source: str | None = None
    stream: str = "default"
    request_id: str | None = None
    verifier_key_id: str | None = None
    evidence: Mapping[str, str] = field(default_factory=dict)  # stage/eval result digests
    # Repository snapshots in the bundle (identity -> metadata time), for rollback checks.
    snapshots: Mapping[str, str] = field(default_factory=dict)
    api_version: str = API_VERSION
    kind: str = "Receipt"

    def __post_init__(self) -> None:
        _require_kind(self, "Receipt")
        for name in ("manifest_digest", "statement_digest", "assessment_digest", "policy_digest"):
            _require_digest(getattr(self, name), name)

    @property
    def accepted(self) -> bool:
        return self.verdict is Verdict.PASSED
