"""Streaming hashing. Nothing here ever holds more than one block in memory."""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

BLOCK = 1 << 20
CHUNK_SIZE = 64 * BLOCK  # recorded in each manifest, so changing it never breaks old bundles


class _Reader(Protocol):
    def read(self, n: int, /) -> bytes: ...


class _Writer(Protocol):
    def write(self, data: bytes, /) -> object: ...


@dataclass(frozen=True, slots=True)
class FileDigest:
    size: int
    sha256: str
    chunks: tuple[str, ...]  # per-chunk sha256; empty when the content fits in one chunk


def hash_stream(
    stream: _Reader,
    *,
    sink: _Writer | None = None,
    chunk_size: int = CHUNK_SIZE,
    on_bytes: Callable[[int], None] | None = None,
) -> FileDigest:
    """Hash a stream in one pass, optionally copying it to ``sink``.

    Besides the whole-content sha256, a sha256 is kept per ``chunk_size`` block. That lets a
    verifier say *where* a large file is damaged, resume an interrupted verification, and split
    a file across volumes. ``on_bytes`` is called before each block is consumed and may raise to
    abort (used for decompression budgets).
    """
    whole, part = hashlib.sha256(), hashlib.sha256()
    filled = size = 0
    chunks: list[str] = []
    while True:
        block = stream.read(min(BLOCK, chunk_size - filled))
        if not block:
            break
        if on_bytes:
            on_bytes(len(block))
        whole.update(block)
        part.update(block)
        if sink:
            sink.write(block)
        size += len(block)
        filled += len(block)
        if filled == chunk_size:
            chunks.append(part.hexdigest())
            part, filled = hashlib.sha256(), 0
    if filled and chunks:
        chunks.append(part.hexdigest())
    return FileDigest(size, whole.hexdigest(), tuple(chunks) if len(chunks) > 1 else ())
