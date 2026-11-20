"""Deterministic traversal of input trees, and read-only views of the files found.

Links are recorded and never followed. Names that cannot be bundle paths are reported in an
escaped form and never descended into.
"""

import io
import os
import posixpath
import stat
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from superscrubber104.core.errors import ConfigError
from superscrubber104.core.model import ArtifactRef, EntryType
from superscrubber104.core.paths import escape_name, is_bundle_path


@dataclass(frozen=True, slots=True)
class Source:
    path: str  # bundle path, or an escaped name when ``safe`` is False
    safe: bool
    location: Path
    entry_type: EntryType
    link_target: str | None = None


def plan_inputs(inputs: Sequence[Path]) -> list[tuple[str, Path]]:
    """Map inputs to bundle path prefixes.

    A single directory becomes the bundle root (its contents sit at the top level). Otherwise
    each input is placed under its own name, which must be unique.
    """
    for path in inputs:
        if not path.exists() and not path.is_symlink():
            raise ConfigError(f"input does not exist: {path}")
    if len(inputs) == 1 and inputs[0].is_dir() and not inputs[0].is_symlink():
        return [("", inputs[0])]
    planned: dict[str, Path] = {}
    for path in inputs:
        name = path.resolve().name if path.name in ("", ".", "..") else path.name
        if not is_bundle_path(name):
            raise ConfigError(f"input name cannot be used as a bundle path: {name!r}")
        if name in planned:
            raise ConfigError(f"two inputs are both named {name!r}")
        planned[name] = path
    return list(planned.items())


_is_junction = getattr(os.path, "isjunction", lambda _path: False)  # Python 3.12+


def _classify(location: Path) -> tuple[EntryType, str | None]:
    if location.is_symlink() or _is_junction(location):
        return EntryType.SYMLINK, str(location.readlink()).replace("\\", "/")
    mode = location.lstat().st_mode
    if stat.S_ISDIR(mode):
        return EntryType.DIRECTORY, None
    if stat.S_ISREG(mode):
        return EntryType.FILE, None
    return EntryType.OTHER, None


def scan(prefix: str, location: Path, *, safe: bool = True) -> Iterator[Source]:
    """Yield every entry under ``location``, parents before children, in name order."""
    entry_type, target = _classify(location)
    if prefix:
        yield Source(prefix, safe, location, entry_type, target)
    if entry_type is not EntryType.DIRECTORY or not safe:
        return
    for name in sorted(child.name for child in location.iterdir()):
        child_safe = is_bundle_path(name)
        child = name if child_safe else escape_name(name)
        yield from scan(f"{prefix}/{child}" if prefix else child, location / name, safe=child_safe)


_HEAD_CACHE = 65536


class FileView:
    """An on-disk file as handlers see it."""

    def __init__(
        self,
        ref: ArtifactRef,
        location: Path,
        size: int,
        sha256: str | None,
        lookup: Callable[[str], "FileView | None"] | None = None,
    ) -> None:
        self.ref = ref
        self.size = size
        self.sha256 = sha256
        self._location = location
        self._lookup = lookup
        self._head: bytes | None = None

    @property
    def location(self) -> Path:
        """Where the bytes are on disk; for external scanners, never for handlers."""
        return self._location

    def head(self, n: int = 65536) -> bytes:
        # Every handler's detect() reads the head; read it from disk once.
        if n > _HEAD_CACHE:
            with self._location.open("rb") as stream:
                return stream.read(n)
        if self._head is None:
            with self._location.open("rb") as stream:
                self._head = stream.read(_HEAD_CACHE)
        return self._head[:n]

    def open(self) -> BinaryIO:
        return self._location.open("rb")

    def resolve(self, relative: str) -> "FileView | None":
        if self._lookup is None or self.ref.nested:
            return None
        target = posixpath.normpath(posixpath.join(posixpath.dirname(self.ref.path), relative))
        if target.startswith(("../", "/")) or target == "..":
            return None
        return self._lookup(target)


class BytesView:
    """A small archive member held in memory: no scratch file to write, scan and delete."""

    def __init__(self, ref: ArtifactRef, data: bytes, sha256: str | None) -> None:
        self.ref = ref
        self.size = len(data)
        self.sha256 = sha256
        self._data = data

    def head(self, n: int = 65536) -> bytes:
        return self._data[:n]

    def open(self) -> BinaryIO:
        return io.BytesIO(self._data)

    def resolve(self, relative: str) -> None:
        return None


class HeadView:
    """A view of content that was streamed but not kept: only its first bytes are available."""

    def __init__(self, ref: ArtifactRef, head: bytes, size: int, sha256: str | None) -> None:
        self.ref = ref
        self.size = size
        self.sha256 = sha256
        self._head = head

    def head(self, n: int = 65536) -> bytes:
        return self._head[:n]

    def open(self) -> BinaryIO:
        raise OSError(f"{self.ref}: content was not retained")

    def resolve(self, relative: str) -> None:
        return None
