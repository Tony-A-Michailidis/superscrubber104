"""Extension interfaces: handlers, unit assemblers, plugins and stagers.

Handlers see artifacts only through ``ArtifactView``: read-only bytes, no filesystem paths, so a
handler cannot wander outside the artifact it was given, and archive members look the same as
files on disk.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import BinaryIO, Protocol, runtime_checkable

from airlock.core.canonical import JSON
from airlock.core.model import (
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
from airlock.core.rules import FindingFactory


class ArtifactView(Protocol):
    ref: ArtifactRef
    size: int
    sha256: str

    def head(self, n: int = 65536) -> bytes:
        """The first ``n`` bytes (fewer if the artifact is shorter). Cheap; used by detect()."""
        ...

    def open(self) -> BinaryIO:
        """A fresh read-only stream from the start of the artifact."""
        ...

    def sibling(self, name: str) -> "ArtifactView | None":
        """Another artifact in the same directory (e.g. a shard index next to a shard)."""
        ...


@dataclass(frozen=True, slots=True)
class Detection:
    kind: str  # e.g. "model.safetensors"
    confidence: int  # 0-100; 100 means a structural match (magic bytes plus a parsed header)


@dataclass(frozen=True, slots=True)
class Inspection:
    """Everything a handler learned from one pass over an artifact."""

    kind: str
    media_type: str | None = None
    metadata: Mapping[str, JSON] = field(default_factory=dict)
    components: tuple[Component, ...] = ()
    claims: tuple[UnitClaim, ...] = ()
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True, slots=True)
class Context:
    """What checks may use: policy, the finding factory, plugins and the evaluation date."""

    policy: Policy
    findings: FindingFactory
    plugins: Mapping[str, "Plugin"]
    today: date


@runtime_checkable
class Handler(Protocol):
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

    def assemble(
        self, claims: Sequence[UnitClaim], ctx: Context
    ) -> Iterable[tuple[Unit, Sequence[Finding]]]:
        """Group claims by root into units, and run completeness and consistency checks."""
        ...


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

    def accepts(self, unit: Unit) -> bool: ...

    def stage(self, bundle: BundleView, unit: Unit, target: Mapping[str, JSON]) -> StageResult:
        """Place a verified unit into a high-side target (registry, repo, model store, ...)."""
        ...
