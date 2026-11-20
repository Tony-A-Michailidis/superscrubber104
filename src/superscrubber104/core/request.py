"""Transfer request: the declared intent that pack and verify check a bundle against.

The request is written on the packing side, so the receiving side treats it as a claim. Its
listed approvers say who is *expected* to sign; whether a signature counts is decided only by
the keys pinned in the receiving side's policy.
"""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from superscrubber104.core.canonical import sha256_digest
from superscrubber104.core.model import API_VERSION, UnitKind, UpstreamRef
from superscrubber104.core.paths import path_matches
from superscrubber104.core.policy import KEY_ID
from superscrubber104.core.yamlio import Reader, load_yaml, load_yaml_file


class Direction(StrEnum):
    LOW_TO_HIGH = "low-to-high"  # the only direction phase 1 accepts for bundles


class Profile(StrEnum):
    ROUTINE = "routine"
    EMERGENCY = "emergency"  # minimal fix for a critical vulnerability (phase 1c)


@dataclass(frozen=True, slots=True)
class Owner:
    name: str
    contact: str | None = None


@dataclass(frozen=True, slots=True)
class Approver:
    name: str
    role: str
    key_id: str | None = None


@dataclass(frozen=True, slots=True)
class ContentEntry:
    """One expected item. ``unit`` requires that a unit of that kind forms under ``paths``."""

    name: str
    paths: tuple[str, ...]
    unit: UnitKind | None = None
    upstream: UpstreamRef | None = None

    def covers(self, path: str) -> bool:
        return any(path_matches(pattern, path) for pattern in self.paths)


@dataclass(frozen=True, slots=True)
class TransferRequest:
    id: str
    title: str
    purpose: str
    owner: Owner
    source: str
    destination: str
    direction: Direction
    contents: tuple[ContentEntry, ...]
    digest: str  # of the request file's exact bytes, which travel verbatim in the bundle
    stream: str = "default"  # ordering scope for recurring transfers
    profile: Profile = Profile.ROUTINE
    approvers: tuple[Approver, ...] = ()
    allow_undeclared: bool = False

    @property
    def corpora(self) -> tuple[str, ...]:
        """Paths declared as knowledge bases: their documents will be fed to a model."""
        return tuple(
            path
            for entry in self.contents
            if entry.unit is UnitKind.KNOWLEDGE_BASE
            for path in entry.paths
        )

    def entries_for(self, path: str) -> tuple[ContentEntry, ...]:
        """Every content entry that declares ``path``. A file may belong to several."""
        return tuple(entry for entry in self.contents if entry.covers(path))


def load_request(path: Path) -> TransferRequest:
    data, raw = load_yaml_file(path)
    return _parse(data, raw, str(path))


def parse_request(raw: bytes, source: str) -> TransferRequest:
    return _parse(load_yaml(raw, source), raw, source)


def _upstream(section: Reader | None) -> UpstreamRef | None:
    if section is None:
        return None
    upstream = UpstreamRef(
        type=section.req_str("type"),
        reference=section.req_str("reference"),
        revision=section.opt_str("revision"),
        digest=section.opt_str("digest"),
    )
    section.done()
    return upstream


def _parse(data: object, raw: bytes, source: str) -> TransferRequest:
    doc = Reader(data, source=source)
    if doc.req_str("apiVersion") != API_VERSION:
        raise doc.error(f"unsupported apiVersion; expected {API_VERSION!r}", "apiVersion")
    if doc.req_str("kind") != "TransferRequest":
        raise doc.error("expected kind: TransferRequest", "kind")

    meta = doc.section("metadata")
    request_id, title = meta.req_str("id"), meta.req_str("title")
    meta.done()

    spec = doc.section("spec")
    owner_section = spec.section("owner")
    owner = Owner(owner_section.req_str("name"), owner_section.opt_str("contact"))
    owner_section.done()

    approvers = []
    for a in spec.sections("approvers"):
        key_id = a.opt_str("keyId")
        if key_id is not None and not KEY_ID.match(key_id):
            raise a.error("expected a key id such as 'ed25519:<64 hex characters>'", "keyId")
        approvers.append(Approver(a.req_str("name"), a.req_str("role"), key_id))
        a.done()

    contents = []
    for c in spec.sections("contents"):
        paths = c.str_list("paths")
        if not paths:
            raise c.error("at least one path glob is required", "paths")
        contents.append(
            ContentEntry(
                name=c.req_str("name"),
                paths=paths,
                unit=c.opt_enum("unit", UnitKind),
                upstream=_upstream(c.opt_section("upstream")),
            )
        )
        c.done()
    names = [c.name for c in contents]
    if len(set(names)) != len(names):
        raise spec.error("content names must be unique", "contents")

    request = TransferRequest(
        id=request_id,
        title=title,
        purpose=spec.req_str("purpose"),
        owner=owner,
        source=spec.req_str("source"),
        destination=spec.req_str("destination"),
        direction=spec.enum("direction", Direction),
        contents=tuple(contents),
        stream=spec.opt_str("stream") or "default",
        profile=spec.opt_enum("profile", Profile) or Profile.ROUTINE,
        approvers=tuple(approvers),
        allow_undeclared=bool(spec.opt_bool("allowUndeclared")),
        digest=sha256_digest(raw),
    )
    spec.done()
    doc.done()
    return request
