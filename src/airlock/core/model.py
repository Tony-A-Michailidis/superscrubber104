"""Core data models shared by every module (see docs/design/17-core-models.md).

All models are frozen dataclasses. Serialisation goes through ``airlock.core.serde`` and every
document that is hashed or signed is encoded with ``airlock.core.canonical``.
"""

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from airlock.core.canonical import JSON
from airlock.core.paths import validate_bundle_path

API_VERSION = "airlock/v1alpha1"

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_kind(obj: object, expected: str) -> None:
    api_version = getattr(obj, "api_version")  # noqa: B009
    kind = getattr(obj, "kind")  # noqa: B009
    if api_version != API_VERSION:
        raise ValueError(f"unsupported apiVersion {api_version!r}; expected {API_VERSION!r}")
    if kind != expected:
        raise ValueError(f"kind must be {expected!r}, got {kind!r}")


def _require_digest(value: str | None, name: str) -> None:
    if value is not None and not _DIGEST.match(value):
        raise ValueError(f"{name} must be 'sha256:<64 hex>', got {value!r}")


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
    """What policy decides to do about a finding."""

    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_APPROVAL = "require-approval"
    BLOCK = "block"


class Verdict(StrEnum):
    PASSED = "passed"
    NEEDS_APPROVAL = "needs-approval"
    BLOCKED = "blocked"


class Stage(StrEnum):
    PACK = "pack"
    VERIFY = "verify"
    OFFLINE_CHECK = "offline-check"
    INSPECT = "inspect"


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
    REPO_MIRROR = "repo-mirror"
    CONTAINER_IMAGE = "container-image"
    VM_IMAGE = "vm-image"
    PATCH_SET = "patch-set"
    KNOWLEDGE_BASE = "knowledge-base"


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
    BUNDLE = "bundle"
    REQUEST = "request"


# --- Identity -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolRef:
    """The tool that produced a result: an airlock handler, or a plugin and its data versions."""

    name: str
    version: str
    extra: Mapping[str, str] | None = None  # e.g. {"dbVersion": "27412", "dbAge": "P2D"}


@dataclass(frozen=True, slots=True, order=True)
class ArtifactRef:
    """Location of an artifact: a bundle path, plus the path inside nested archives if any."""

    path: str
    member: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_bundle_path(self.path)
        for part in self.member:
            validate_bundle_path(part)

    @property
    def display(self) -> str:
        """Human form, e.g. ``images/app.tar!/layer.tar!/usr/bin/x``. Not parsed back."""
        return "!/".join((self.path, *self.member))

    def __str__(self) -> str:
        return self.display


# --- Artifacts, components, units ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Artifact:
    ref: ArtifactRef
    entry_type: EntryType
    size: int
    kind: str  # handler classification, e.g. "model.safetensors"; "unclassified" if none
    hashes: Mapping[str, str] = field(default_factory=dict)
    link_target: str | None = None  # symlinks are recorded, never followed
    media_type: str | None = None  # detected from content, not the extension
    handler: ToolRef | None = None
    metadata: Mapping[str, JSON] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("size must be non-negative")
        if self.entry_type is EntryType.FILE and "sha256" not in self.hashes:
            raise ValueError(f"{self.ref}: files must have a sha256 hash")
        for algorithm, value in self.hashes.items():
            if not re.fullmatch(r"[0-9a-f]+", value):
                raise ValueError(f"{self.ref}: {algorithm} must be lowercase hex")
        if "sha256" in self.hashes and not _SHA256_HEX.match(self.hashes["sha256"]):
            raise ValueError(f"{self.ref}: sha256 must be 64 lowercase hex characters")
        if (self.link_target is not None) != (self.entry_type in _LINK_TYPES):
            raise ValueError(f"{self.ref}: link_target is set if and only if this is a link")

    @property
    def sha256(self) -> str | None:
        return self.hashes.get("sha256")


_LINK_TYPES = frozenset({EntryType.SYMLINK, EntryType.HARDLINK})


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
    """Where a component came from, precisely enough to fetch the identical bytes again."""

    type: str  # "huggingface", "ollama", "oci", "pypi", "npm", "url", ...
    reference: str  # "Qwen/Qwen2.5-7B-Instruct", "registry.example/app", a URL
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
    evidence: tuple[ArtifactRef, ...] = ()
    children: tuple[str, ...] = ()
    properties: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UnitMember:
    role: str  # "weights-shard", "tokenizer", "chat-template", "lockfile", "wheel", ...
    artifact: ArtifactRef


@dataclass(frozen=True, slots=True)
class UnitClaim:
    """A handler's claim that an artifact belongs to a unit; assemblers build units from these."""

    kind: UnitKind
    root: str
    role: str
    artifact: ArtifactRef
    facts: Mapping[str, JSON] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Unit:
    """A typed group of artifacts that only works as a whole."""

    kind: UnitKind
    name: str
    root: str  # bundle path anchoring the unit; unique per kind
    members: tuple[UnitMember, ...] = ()
    components: tuple[str, ...] = ()  # bom_refs
    attributes: Mapping[str, JSON] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_bundle_path(self.root)

    @property
    def id(self) -> str:
        return f"{self.kind.value}:{self.root}"


# --- Findings and assessments -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Subject:
    """What a finding is about."""

    kind: SubjectKind
    artifact: ArtifactRef | None = None
    unit: str | None = None  # unit id, "<kind>:<root>"

    def __post_init__(self) -> None:
        if (self.artifact is not None) != (self.kind is SubjectKind.ARTIFACT):
            raise ValueError("artifact is set if and only if kind is 'artifact'")
        if (self.unit is not None) != (self.kind is SubjectKind.UNIT):
            raise ValueError("unit is set if and only if kind is 'unit'")

    @classmethod
    def of_artifact(cls, ref: ArtifactRef) -> "Subject":
        return cls(SubjectKind.ARTIFACT, artifact=ref)

    @classmethod
    def of_unit(cls, unit: Unit) -> "Subject":
        return cls(SubjectKind.UNIT, unit=unit.id)

    @classmethod
    def bundle(cls) -> "Subject":
        return cls(SubjectKind.BUNDLE)

    @classmethod
    def request(cls) -> "Subject":
        return cls(SubjectKind.REQUEST)

    @property
    def display(self) -> str:
        if self.artifact is not None:
            return self.artifact.display
        if self.unit is not None:
            return self.unit
        return self.kind.value

    @property
    def path(self) -> str | None:
        """Bundle path used for policy path scoping: the artifact path, or the unit root."""
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
    not_assessed_reason: str | None = None

    def __post_init__(self) -> None:
        if (self.not_assessed_reason is not None) != (self.result is Result.NOT_ASSESSED):
            raise ValueError("not_assessed_reason is set if and only if result is not-assessed")


@dataclass(frozen=True, slots=True)
class Decision:
    """The policy engine's decision on one finding, traceable to one policy entry."""

    finding: str  # finding id
    disposition: Disposition
    matched: str  # "rules[4]", "waivers[1]", "defaults.severity.high", "pass"
    approvals_required: int = 0
    waiver: str | None = None


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


def summarize(findings: Iterable[Finding], decisions: Iterable[Decision]) -> Summary:
    results = Counter(f.result for f in findings)
    dispositions = Counter(d.disposition for d in decisions)
    if dispositions[Disposition.BLOCK]:
        verdict = Verdict.BLOCKED
    elif dispositions[Disposition.REQUIRE_APPROVAL]:
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
    """One run of pack, verify or a standalone check. Holds the only timestamps besides custody."""

    tool: ToolRef
    stage: Stage
    started_at: datetime
    finished_at: datetime
    policy_digest: str
    summary: Summary
    plugins: tuple[PluginStatus, ...] = ()
    findings: tuple[Finding, ...] = ()
    decisions: tuple[Decision, ...] = ()
    api_version: str = API_VERSION
    kind: str = "Assessment"

    def __post_init__(self) -> None:
        _require_kind(self, "Assessment")
        _require_digest(self.policy_digest, "policy_digest")
        finding_ids = [f.id for f in self.findings]
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("duplicate finding ids")
        if sorted(d.finding for d in self.decisions) != sorted(finding_ids):
            raise ValueError("every finding needs exactly one decision")


# --- Bundle documents ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Manifest:
    """Deterministic inventory of a bundle. Contains no timestamps or host details."""

    policy_digest: str
    artifacts: tuple[Artifact, ...]
    units: tuple[Unit, ...] = ()
    request_digest: str | None = None
    api_version: str = API_VERSION
    kind: str = "Manifest"

    def __post_init__(self) -> None:
        _require_kind(self, "Manifest")
        _require_digest(self.policy_digest, "policy_digest")
        _require_digest(self.request_digest, "request_digest")
        refs = [a.ref for a in self.artifacts]
        if refs != sorted(refs) or len(set(refs)) != len(refs):
            raise ValueError("artifacts must be unique and sorted by ref; use Manifest.create")
        unit_ids = [u.id for u in self.units]
        if unit_ids != sorted(unit_ids) or len(set(unit_ids)) != len(unit_ids):
            raise ValueError("units must be unique and sorted by id; use Manifest.create")

    @classmethod
    def create(
        cls,
        *,
        policy_digest: str,
        artifacts: Iterable[Artifact],
        units: Iterable[Unit] = (),
        request_digest: str | None = None,
    ) -> "Manifest":
        """Build a manifest with artifacts and units in canonical order."""
        return cls(
            policy_digest=policy_digest,
            artifacts=tuple(sorted(artifacts, key=lambda a: a.ref)),
            units=tuple(sorted(units, key=lambda u: u.id)),
            request_digest=request_digest,
        )


@dataclass(frozen=True, slots=True)
class BundleDescriptor:
    """``airlock-bundle.json``: the entry point that identifies a directory as a bundle."""

    manifest_digest: str
    layout_version: int = 1
    api_version: str = API_VERSION
    kind: str = "Bundle"

    def __post_init__(self) -> None:
        _require_kind(self, "Bundle")
        _require_digest(self.manifest_digest, "manifest_digest")


@dataclass(frozen=True, slots=True)
class Receipt:
    """Signed high-side import record. Hashes only, so it is safe to send back outbound."""

    manifest_digest: str
    assessment_digest: str
    policy_digest: str
    verifier_key_id: str
    verified_at: datetime
    verdict: Verdict
    api_version: str = API_VERSION
    kind: str = "Receipt"

    def __post_init__(self) -> None:
        _require_kind(self, "Receipt")
        for name in ("manifest_digest", "assessment_digest", "policy_digest"):
            _require_digest(getattr(self, name), name)
