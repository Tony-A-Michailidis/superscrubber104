"""Multi-volume bundles: a payload split across removable media of a fixed size.

``airlock pack --volume-size 25GB`` writes the payload into ``volumes/0001/``, ``volumes/0002/``,
... instead of ``payload/``. Each volume holds whole files under ``payload/`` where they fit, and
pieces of larger files under ``parts/``. Nothing about the manifest changes: it still lists every
file with its hashes, so the snapshot's identity is the same however it was cut.

* ``volumes.json`` at the bundle root is the **volume index**: for every volume, every file or
  piece it holds, at which offset of which file, with its size and sha256. It is one of the
  signed files, so where each byte is supposed to be is covered by the bundle signature.
* ``volume.json`` in each volume repeats that volume's part of the index. It is not signed: it
  lets ``airlock volume check`` confirm one medium on its own (at writing, at each hand-over),
  before the whole bundle is assembled. Verification never relies on it.

Verify reads each volume from ``volumes/NNNN`` under the bundle or from any directory given with
``--volume`` (a mounted medium), checks every piece against the index, and reassembles split
files in a scratch directory before checking them against the manifest.
"""

import hashlib
import json
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from airlock.core.canonical import canonical_bytes
from airlock.core.errors import ConfigError
from airlock.core.model import API_VERSION, EntryType
from airlock.core.serde import from_data, to_data
from airlock.hashing import BLOCK, FileDigest, hash_stream
from airlock.walker import Source

INDEX = "volumes.json"
DIRECTORY = "volumes"
VOLUME_FILE = "volume.json"
MINIMUM_SIZE = 1 << 20


@dataclass(frozen=True, slots=True)
class Piece:
    path: str  # bundle path of the file this is part of
    offset: int  # where in that file the piece starts
    size: int
    sha256: str
    stored: str  # where it is inside the volume: "payload/<path>" or "parts/<n>.part"
    whole: bool = True  # False for one piece of a file split across volumes


@dataclass(frozen=True, slots=True)
class Volume:
    number: int
    bytes: int
    pieces: tuple[Piece, ...] = ()

    @property
    def name(self) -> str:
        return f"{self.number:04d}"


@dataclass(frozen=True, slots=True)
class VolumeIndex:
    volume_size: int
    volumes: tuple[Volume, ...]
    api_version: str = API_VERSION
    kind: str = "VolumeIndex"

    def pieces_of(self, path: str) -> list[tuple[Volume, Piece]]:
        found = [(v, p) for v in self.volumes for p in v.pieces if p.path == path]
        return sorted(found, key=lambda vp: vp[1].offset)


@dataclass(frozen=True, slots=True)
class VolumeLabel:
    """``volume.json``: one medium's own copy of its part of the index."""

    number: int
    count: int
    index_sha256: str  # ties the medium to one bundle's index
    pieces: tuple[Piece, ...]
    api_version: str = API_VERSION
    kind: str = "VolumeLabel"


class VolumeWriter:
    """Fills volumes in order. A file that fits in one volume is never split; a file larger than
    a volume is split across as many as it needs."""

    def __init__(self, bundle: Path, volume_size: int) -> None:
        if volume_size < MINIMUM_SIZE:
            raise ConfigError(f"volume size must be at least {MINIMUM_SIZE} bytes")
        self.root = bundle / DIRECTORY
        self.size = volume_size
        self.volumes: list[list[Piece]] = [[]]
        self.used = [0]
        self.parts = 0

    def _new_volume(self) -> None:
        self.volumes.append([])
        self.used.append(0)

    def _dir(self) -> Path:
        return self.root / f"{len(self.volumes):04d}"

    def directory(self, path: str) -> None:
        (self._dir() / "payload" / path).mkdir(parents=True, exist_ok=True)

    def write(self, path: str, stream: BinaryIO, size: int, chunk_size: int) -> FileDigest:
        free = self.size - self.used[-1]
        if size > free and size <= self.size and self.used[-1] > 0:
            self._new_volume()
        if size <= self.size - self.used[-1]:
            target = self._dir() / "payload" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as sink:
                digest = hash_stream(stream, sink=sink, chunk_size=chunk_size)
            self.volumes[-1].append(Piece(path, 0, digest.size, digest.sha256, f"payload/{path}"))
            self.used[-1] += digest.size
            return digest
        # Too large for one volume: split it, filling each volume in turn.
        pieces: list[tuple[int, Path]] = []
        offset = 0
        while True:
            room = self.size - self.used[-1]
            if room <= 0:
                self._new_volume()
                continue
            self.parts += 1
            stored = f"parts/{self.parts:06d}.part"
            target = self._dir() / stored
            target.parent.mkdir(parents=True, exist_ok=True)
            written, piece_hash = _copy(stream, target, room)
            if written == 0:
                target.unlink()
                self.parts -= 1
                break
            self.volumes[-1].append(Piece(path, offset, written, piece_hash, stored, whole=False))
            pieces.append((offset, target))
            self.used[-1] += written
            offset += written
        # Re-hash the pieces in order for the chunked digest the manifest needs.
        return hash_stream(_Concat([p for _, p in pieces]), chunk_size=chunk_size)

    def finish(self) -> VolumeIndex:
        volumes = tuple(
            Volume(number, used, tuple(pieces))
            for number, (pieces, used) in enumerate(zip(self.volumes, self.used, strict=True), 1)
            if pieces or number == 1
        )
        index = VolumeIndex(self.size, volumes)
        index_sha = hashlib.sha256(canonical_bytes(to_data(index))).hexdigest()
        for volume in volumes:
            label = VolumeLabel(volume.number, len(volumes), index_sha, volume.pieces)
            directory = self.root / volume.name
            directory.mkdir(parents=True, exist_ok=True)
            (directory / VOLUME_FILE).write_bytes(canonical_bytes(to_data(label)))
        return index


class _Concat:
    """Read several files as one stream."""

    def __init__(self, paths: Sequence[Path]) -> None:
        self.paths = list(paths)
        self.current: BinaryIO | None = None

    def read(self, n: int) -> bytes:
        while self.paths or self.current:
            if self.current is None:
                self.current = self.paths.pop(0).open("rb")
            data = self.current.read(n)
            if data:
                return data
            self.current.close()
            self.current = None
        return b""


def _copy(stream: BinaryIO, target: Path, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    written = 0
    with target.open("xb") as sink:
        while written < limit:
            block = stream.read(min(BLOCK, limit - written))
            if not block:
                break
            sink.write(block)
            digest.update(block)
            written += len(block)
    return written, digest.hexdigest()


def write_index(bundle: Path, index: VolumeIndex) -> bytes:
    data = canonical_bytes(to_data(index))
    (bundle / INDEX).write_bytes(data)
    return data


def load_index(data: bytes) -> VolumeIndex:
    return from_data(VolumeIndex, json.loads(data))


def index_sha256(index: VolumeIndex) -> str:
    return hashlib.sha256(canonical_bytes(to_data(index))).hexdigest()


# --- reading ------------------------------------------------------------------------------------


@dataclass(slots=True)
class Resolved:
    """The payload as verify sees it, assembled from the volumes."""

    sources: dict[str, Source] = field(default_factory=dict)
    missing_volumes: list[int] = field(default_factory=list)
    damaged: dict[str, list[dict[str, object]]] = field(default_factory=dict)  # path -> pieces
    unexpected: list[Source] = field(default_factory=list)


def find_volumes(bundle: Path, extra: Iterable[Path], index: VolumeIndex) -> dict[int, Path]:
    """Volume number -> directory: under the bundle, or a medium given on the command line."""
    expected = index_sha256(index)
    found: dict[int, Path] = {}
    candidates = [bundle / DIRECTORY / v.name for v in index.volumes]
    for directory in extra:
        candidates += [directory, *sorted(p for p in directory.glob("[0-9][0-9][0-9][0-9]"))]
        candidates += sorted(directory.glob(f"{DIRECTORY}/[0-9][0-9][0-9][0-9]"))
    for directory in candidates:
        label_path = directory / VOLUME_FILE
        if not label_path.is_file():
            continue
        try:
            label = from_data(VolumeLabel, json.loads(label_path.read_bytes()))
        except (ValueError, TypeError):
            continue
        if label.index_sha256 == expected and label.number not in found:
            found[label.number] = directory
    return found


def resolve(bundle: Path, index: VolumeIndex, extra: Iterable[Path], scratch: Path) -> Resolved:
    out = Resolved()
    located = find_volumes(bundle, extra, index)
    out.missing_volumes = [v.number for v in index.volumes if v.number not in located]
    split: dict[str, list[tuple[Volume, Piece]]] = {}
    expected_files: dict[int, set[str]] = {}
    for volume in index.volumes:
        expected_files[volume.number] = {p.stored for p in volume.pieces}
        directory = located.get(volume.number)
        for piece in volume.pieces:
            if not piece.whole:
                split.setdefault(piece.path, []).append((volume, piece))
                continue
            if directory is None:
                continue
            location = directory / piece.stored
            if location.is_file():
                out.sources[piece.path] = Source(piece.path, True, location, EntryType.FILE)
    for path, pieces in split.items():
        pieces.sort(key=lambda vp: vp[1].offset)
        if any(v.number not in located for v, _ in pieces):
            continue
        target = scratch / f"{len(out.sources):08d}.joined"
        bad = []
        with target.open("wb") as sink:
            for volume, piece in pieces:
                location = located[volume.number] / piece.stored
                if not location.is_file():
                    bad.append(
                        {"volume": volume.number, "piece": piece.stored, "problem": "missing"}
                    )
                    continue
                with location.open("rb") as stream:
                    digest = hash_stream(stream, sink=sink)
                if digest.sha256 != piece.sha256 or digest.size != piece.size:
                    bad.append(
                        {"volume": volume.number, "piece": piece.stored, "problem": "differs"}
                    )
        if bad:
            out.damaged[path] = bad
        out.sources[path] = Source(path, True, target, EntryType.FILE)
    for number, directory in located.items():
        for item in _files(directory):
            relative = item.relative_to(directory).as_posix()
            if relative == VOLUME_FILE or relative in expected_files.get(number, set()):
                continue
            path = relative.removeprefix("payload/")
            out.unexpected.append(Source(f"{path}", True, item, EntryType.FILE))
    return out


def _files(directory: Path) -> Iterator[Path]:
    for item in sorted(directory.rglob("*")):
        if item.is_file() or item.is_symlink():
            yield item


def check_volume(directory: Path) -> tuple[VolumeLabel, list[dict[str, object]]]:
    """Check one medium on its own against its ``volume.json``: every piece present and intact."""
    try:
        label = from_data(VolumeLabel, json.loads((directory / VOLUME_FILE).read_bytes()))
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"{directory} is not an airlock volume: {exc}") from exc
    problems: list[dict[str, object]] = []
    listed = {p.stored for p in label.pieces}
    for piece in label.pieces:
        location = directory / piece.stored
        if not location.is_file():
            problems.append({"piece": piece.stored, "problem": "missing"})
            continue
        with location.open("rb") as stream:
            digest = hash_stream(stream)
        if digest.sha256 != piece.sha256 or digest.size != piece.size:
            problems.append({"piece": piece.stored, "problem": "differs"})
    for item in _files(directory):
        relative = item.relative_to(directory).as_posix()
        if relative != VOLUME_FILE and relative not in listed:
            problems.append({"piece": relative, "problem": "not listed"})
    return label, problems
