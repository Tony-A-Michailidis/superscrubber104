"""Helpers shared by all handlers: names, roots, bounded reads, claims."""

import json
import posixpath
import re
from collections.abc import Mapping
from typing import Any

from superscrubber104.core.canonical import jsonable
from superscrubber104.core.interfaces import ArtifactView
from superscrubber104.core.model import ArtifactRef, UnitClaim, UnitKind


class TooLarge(ValueError):
    pass


_SECRET_NAME = re.compile(
    r"(?i)(token|secret|passw(or)?d|api[_-]?key|access[_-]?key|auth|credential|private[_-]?key|bearer)"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(\$\{?|\{\{|<|%|your[_-]|change[_-]?me|xxx|example|placeholder|todo|\*+$)"
)


def is_literal_secret(name: str, value: object) -> bool:
    """A setting whose name says credential and whose value looks like a real one.

    References (``${VAR}``, ``{{ secret }}``), placeholders and short values are not; the value
    itself is never recorded by callers.
    """
    if not isinstance(value, str) or not _SECRET_NAME.search(name):
        return False
    stripped = value.strip()
    return len(stripped) >= 8 and not _PLACEHOLDER.match(stripped) and len(set(stripped)) > 3


# Tests, fixtures, examples and documentation: what a finding there shows is usually a dummy,
# so handlers report it at low severity with the context "test or example path".
TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests__|testing|test_?data|testdata|fixtures?|examples?|samples?|docs?"
    r"|spec)(/|$)|(^|/)test_[^/]*$|_test\.[a-z]+$|\.(test|spec)\.[a-z]+$"
    r"|(^|/)(examples?|samples?)[-_.][^/]*$"
)
TEST_CONTEXT = "test or example path"


def full_path(ref: ArtifactRef) -> str:
    """The innermost path: the bundle path, or the path inside the innermost archive."""
    return (ref.path, *ref.member)[-1]


def name_of(ref: ArtifactRef) -> str:
    return posixpath.basename(full_path(ref))


def parent_of(ref: ArtifactRef) -> ArtifactRef:
    """The directory an artifact sits in, as a unit root.

    ``ArtifactRef(".")`` stands for the bundle root; for a member at the top of an archive it is
    the archive itself.
    """
    if ref.member:
        directory = posixpath.dirname(ref.member[-1])
        if directory:
            return ArtifactRef(ref.path, (*ref.member[:-1], directory), unsafe=ref.unsafe)
        return ArtifactRef(ref.path, ref.member[:-1], unsafe=ref.unsafe)
    directory = posixpath.dirname(ref.path)
    return ArtifactRef(directory or ".", unsafe=ref.unsafe)


def ancestor(ref: ArtifactRef, levels: int) -> ArtifactRef:
    for _ in range(levels):
        ref = parent_of(ref)
    return ref


def sibling(ref: ArtifactRef, name: str) -> ArtifactRef:
    """Another file in the same directory (for naming expected files that may be missing)."""
    if ref.member:
        directory = posixpath.dirname(ref.member[-1])
        member = posixpath.join(directory, name) if directory else name
        return ArtifactRef(ref.path, (*ref.member[:-1], member), unsafe=ref.unsafe)
    return ArtifactRef(posixpath.join(posixpath.dirname(ref.path), name), unsafe=ref.unsafe)


def relative_to(ref: ArtifactRef, root: ArtifactRef) -> str | None:
    """``ref``'s path below ``root`` (a unit root as made by ``parent_of``), or None."""
    if not root.member:
        if root.path == "." and not ref.member:
            return ref.path  # below the bundle root
        if not ref.member and ref.path.startswith(root.path + "/"):
            return ref.path[len(root.path) + 1 :]  # below a directory
        if ref.path == root.path and len(ref.member) == 1:
            return ref.member[0]  # at the top of an archive
        return None
    same_archive = ref.path == root.path and ref.member[:-1] == root.member[:-1]
    if same_archive and len(ref.member) == len(root.member):
        prefix = root.member[-1] + "/"
        if ref.member[-1].startswith(prefix):
            return ref.member[-1][len(prefix) :]  # below a directory inside an archive
    if (
        ref.path == root.path
        and ref.member[:-1] == root.member
        and len(ref.member) == len(root.member) + 1
    ):
        return ref.member[-1]  # at the top of a nested archive
    return None


def items(value: object) -> list[Any]:
    """A JSON array, or an empty one: delivered documents may have any shape."""
    return value if isinstance(value, list) else []


def mapping(value: object) -> dict[str, Any]:
    """``value`` if it is a JSON object, else an empty one."""
    return value if isinstance(value, dict) else {}


def read_bytes(view: ArtifactView, limit: int) -> bytes:
    if view.size > limit:
        raise TooLarge(f"{view.size} bytes is more than the {limit}-byte limit for this file")
    with view.open() as stream:
        return stream.read(limit + 1)


def read_text(view: ArtifactView, limit: int = 1 << 20) -> str:
    return read_bytes(view, limit).decode("utf-8", "replace")


def _constant(value: str) -> str:
    return value  # NaN and Infinity stay as their names; canonical JSON has no floats


def read_json(view: ArtifactView, limit: int = 64 << 20) -> Any:
    """Parse a JSON file of bounded size. Raises TooLarge or ValueError."""
    raw = read_bytes(view, limit)
    return json.loads(raw.decode("utf-8-sig"), parse_constant=_constant)


def make_claim(
    view: ArtifactView,
    kind: UnitKind,
    role: str,
    facts: Mapping[str, object] | None = None,
    *,
    root: ArtifactRef | None = None,
) -> UnitClaim:
    return UnitClaim(
        kind=kind,
        root=root or parent_of(view.ref),
        role=role,
        artifact=view.ref,
        sha256=view.sha256,
        facts={key: jsonable(value) for key, value in (facts or {}).items()},
    )
