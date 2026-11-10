"""Extension interfaces: handlers, unit assemblers, bundle checks, plugins and stagers.

Handlers see artifacts only through ``ArtifactView``: read-only bytes, no filesystem paths, so a
handler cannot wander outside the artifact it was given, and archive members look the same as
files on disk.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import BinaryIO, Protocol, runtime_checkable

from airlock.core.canonical import JSON
from airlock.core.model import (
    Analysis,
    Artifact,
    ArtifactRef,
    Component,
    Finding,
    Manifest,
    PluginStatus,
    Unit,
    UnitClaim,
    UnitKind,
)
from airlock.core.policy import Policy
from airlock.core.rules import Recorder


class ArtifactView(Protocol):
    ref: ArtifactRef
    size: int
    sha256: str | None

    def head(self, n: int = 65536) -> bytes:
        """The first ``n`` bytes (fewer if the artifact is shorter). Cheap; used by detect()."""
        ...

    def open(self) -> BinaryIO:
        """A fresh read-only stream from the start of the artifact."""
        ...

    def resolve(self, relative: str) -> "ArtifactView | None":
        """Another artifact by path relative to this one's directory (``tokenizer.json``,
        ``onnx/model.onnx_data``). Never leaves the delivery; None if absent."""
        ...


class Lookup(Protocol):
    """Read access to any artifact of the delivery, for unit assemblers and bundle checks."""

    def __call__(self, ref: ArtifactRef) -> ArtifactView | None: ...


@dataclass(frozen=True, slots=True)
class Detection:
    kind: str  # e.g. "model.safetensors"
    confidence: int  # 0-100; 100 means a structural match (magic bytes plus a parsed header)


@dataclass(frozen=True, slots=True)
class Inspection:
    """Everything a handler learned from one pass over an artifact."""

    kind: str
    media_type: str | None = None
    # Whatever the format's header holds; coerced to canonical JSON (floats become strings).
    metadata: Mapping[str, object] = field(default_factory=dict)
    components: tuple[Component, ...] = ()
    claims: tuple[UnitClaim, ...] = ()
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True, slots=True)
class Context:
    """What checks may use: policy, the evidence recorder, plugins and the current time."""

    policy: Policy
    recorder: Recorder
    now: datetime
    plugins: Mapping[str, "Plugin"] = field(default_factory=dict)


@runtime_checkable
class Handler(Protocol):
    """Recognises and inspects one family of artifacts.

    Every handler whose ``detect`` matches runs, so a polyglot (an executable that is also a model
    file) is inspected as each thing it is.
    """

    name: str
    version: str
    kinds: frozenset[str]  # kinds this handler can produce

    def detect(self, artifact: ArtifactView) -> Detection | None:
        """Cheap classification from the name and ``head()``. Must not read the whole artifact."""
        ...

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        """One streaming pass: metadata, components, unit claims and findings.

        Never executes, imports or deserialises executable content from the artifact.
        """
        ...


@runtime_checkable
class UnitAssembler(Protocol):
    kind: UnitKind

    def assemble(self, claims: Sequence[UnitClaim], lookup: Lookup, ctx: Context) -> Iterable[Unit]:
        """Group claims by root into units and record completeness and consistency findings."""
        ...


@runtime_checkable
class BundleCheck(Protocol):
    """A check that needs the whole picture: cross-unit requirements (an adapter's base model,
    a knowledge base's embedding model), images referenced by manifests, transfer conformance."""

    name: str

    def check(
        self, manifest: Manifest, analysis: Analysis, lookup: Lookup, ctx: Context
    ) -> None: ...


@runtime_checkable
class Plugin(Protocol):
    """Wrapper around an optional external tool (ClamAV, Syft, qemu-img, ...).

    Concrete capabilities (malware scanning, SBOM generation, image inspection) are separate
    protocols that a plugin also implements.
    """

    name: str

    def status(self, ctx: Context) -> PluginStatus:
        """Presence, version, binary hash and data age. Must not run the tool on content."""
        ...


class BundleView(Protocol):
    """A bundle that has passed verification, as seen by stagers."""

    manifest: Manifest
    analysis: Analysis

    def open(self, ref: ArtifactRef) -> BinaryIO: ...


@dataclass(frozen=True, slots=True)
class StageResult:
    stager: str
    staged: tuple[ArtifactRef, ...]
    findings: tuple[Finding, ...] = ()
    detail: Mapping[str, JSON] = field(default_factory=dict)


@runtime_checkable
class Stager(Protocol):
    name: str

    def accepts(self, item: Unit | Artifact) -> bool: ...

    def stage(
        self, bundle: BundleView, item: Unit | Artifact, target: Mapping[str, JSON]
    ) -> StageResult:
        """Place a verified unit or loose artifact into a receiving-side target."""
        ...
