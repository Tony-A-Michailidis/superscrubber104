"""Transfer request: the declared intent that verify checks the bundle against."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from airlock.core.canonical import JSON, sha256_digest
from airlock.core.model import API_VERSION, UnitKind
from airlock.core.paths import path_matches
from airlock.core.policy import KEY_ID
from airlock.core.yamlio import Reader, load_yaml, load_yaml_file


class Direction(StrEnum):
    LOW_TO_HIGH = "low-to-high"  # the only direction phase 1 accepts


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
    upstream: Mapping[str, JSON] = field(default_factory=dict)


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
    approvers: tuple[Approver, ...] = ()
    allow_undeclared: bool = False

    def entry_for(self, path: str) -> ContentEntry | None:
        """The first content entry that declares ``path``, if any."""
        for entry in self.contents:
            if any(path_matches(pattern, path) for pattern in entry.paths):
                return entry
        return None


def load_request(path: Path) -> TransferRequest:
    data, raw = load_yaml_file(path)
    return _parse(data, raw, str(path))


def parse_request(raw: bytes, source: str) -> TransferRequest:
    return _parse(load_yaml(raw, source), raw, source)


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
            raise a.error("expected a key id such as 'ed25519:0123456789abcdef'", "keyId")
        approvers.append(Approver(a.req_str("name"), a.req_str("role"), key_id))
        a.done()

    contents = []
    for c in spec.sections("contents"):
        paths = c.str_list("paths")
        if not paths:
            raise c.error("at least one path glob is required", "paths")
        upstream = c.raw("upstream")
        if upstream is not None and not isinstance(upstream, dict):
            raise c.error("expected a mapping", "upstream")
        contents.append(
            ContentEntry(
                name=c.req_str("name"),
                paths=paths,
                unit=c.opt_enum("unit", UnitKind),
                upstream=dict(upstream or {}),
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
        approvers=tuple(approvers),
        allow_undeclared=bool(spec.opt_bool("allowUndeclared")),
        digest=sha256_digest(raw),
    )
    spec.done()
    doc.done()
    return request
