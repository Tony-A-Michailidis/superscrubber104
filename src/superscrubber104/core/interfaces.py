"""Extension interfaces: handlers and unit assemblers.

Handlers see artifacts only through ``ArtifactView``: read-only bytes, no filesystem paths, so a
handler cannot wander outside the artifact it was given, and archive members look the same as
files on disk.

The other extension points live with what they extend: external scanners implement
``superscrubber104.scanners.base.Scanner``; checks that need the whole delivery are functions called
from ``superscrubber104.analysis.finish``; staging targets are functions in
``superscrubber104.stage``.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import BinaryIO, Protocol, runtime_checkable

from superscrubber104.core.model import (
    ArtifactRef,
    Component,
    Finding,
    Unit,
    UnitClaim,
    UnitKind,
    Verification,
)
from superscrubber104.core.policy import Policy
from superscrubber104.core.rules import Recorder


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
    # Upstream proof established for artifacts (this one, or others it vouches for, such as
    # the files a signed checksum list names).
    verifications: Mapping[ArtifactRef, tuple[Verification, ...]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Context:
    """What checks may use: policy, the evidence recorder and the current time."""

    policy: Policy
    recorder: Recorder
    now: datetime
    # Path globs whose documents will be fed to a model (knowledge-base corpora): from the
    # transfer request's ``unit: knowledge-base`` entries, or given on the command line.
    corpora: tuple[str, ...] = ()


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
    name: str
    version: str
    kind: UnitKind

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable["Assembly"]:
        """Group claims by root into units and record completeness and consistency findings.

        Works from the claims' facts alone, so units inside archives assemble like any other.
        """
        ...


@dataclass(frozen=True, slots=True)
class Assembly:
    """One unit, the SBOM components it contributes, and what was verified about its members."""

    unit: Unit
    components: tuple[Component, ...] = ()
    verifications: Mapping[ArtifactRef, tuple[Verification, ...]] = field(default_factory=dict)
