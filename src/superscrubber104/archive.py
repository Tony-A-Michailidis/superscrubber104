"""Reading archives without extracting them.

Members are enumerated and their bytes streamed; no member name is ever used as a filesystem
path, so path traversal, link tricks and device nodes can be reported but cannot take effect.
"""

import bz2
import functools
import gzip
import io
import lzma
import stat
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import IO, Any, cast

from superscrubber104.core.model import EntryType


def zstd_module() -> Any:
    """The zstd module: the standard library's from Python 3.14, else the optional backport of the
    same API (``pip install superscrubber104[zstd]``), else None. The core adds no dependency for
    it; without
    either, zstd archives are recorded with their contents not assessed."""
    try:
        from compression import zstd  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        try:
            from backports import zstd  # type: ignore[import-not-found,no-redef,unused-ignore]
        except ImportError:
            return None
    return zstd


ZSTD = zstd_module() is not None
ZSTD_ADVICE = (
    "zstd needs Python 3.14 or later, or the optional backport (pip install "
    "'superscrubber104[zstd]'); "
    "or decompress the archive before packing (for Zarf, build the package with "
    "metadata.uncompressed: true)"
)

# single-stream compression layers
COMPRESSION = frozenset({"gzip", "bzip2", "xz", *(("zstd",) if ZSTD else ())})
CONTAINERS = frozenset({"zip", "tar"})
# recognised, but contents cannot be read
UNSUPPORTED = frozenset({"7z", "rar", *(() if ZSTD else ("zstd",))})


class ExpansionLimit(ValueError):
    """A decompressed stream is larger than its reader allows."""


def _zstd_error() -> type[Exception]:
    """What a damaged zstd stream raises; a stand-in, never raised, when zstd cannot be read."""
    zstd = zstd_module()
    return ExpansionLimit if zstd is None else cast(type[Exception], zstd.ZstdError)


ZstdError = _zstd_error()


# Everything the standard library raises for damaged, truncated or exotic archives.
ARCHIVE_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    tarfile.TarError,
    lzma.LZMAError,
    zlib.error,
    EOFError,
    OSError,
    RuntimeError,
    NotImplementedError,
    ValueError,
    ZstdError,
)

_MAGIC = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
)


def detect_format(head: bytes) -> str | None:
    """Archive format from magic bytes; never from the file name."""
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    if head[257:262] == b"ustar":
        return "tar"
    return None


@dataclass(slots=True)
class Member:
    name: str  # exactly as stored; may be hostile
    entry_type: EntryType
    size: int = 0  # as declared by the archive; not trusted
    mode: int | None = None
    link_target: str | None = None
    encrypted: bool = False
    open: Callable[[], IO[bytes]] | None = None  # None when there is no readable content


class _Capped(io.RawIOBase):
    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream, self._left = stream, limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._stream.read(len(buffer))
        self._left -= len(data)
        if self._left < 0:
            raise ExpansionLimit("expands beyond the size superscrubber104 will read")
        buffer[: len(data)] = data
        return len(data)


def capped(stream: IO[bytes], limit: int) -> IO[bytes]:
    """``stream``, refusing to hand out more than ``limit`` bytes.

    Compressed input is untrusted: a few kilobytes can claim to expand to terabytes. The analyzer's
    own archive walk has a budget; a handler that decompresses something itself reads it through
    this instead.
    """
    return cast(IO[bytes], io.BufferedReader(_Capped(stream, limit)))


def decompress(fmt: str, stream: IO[bytes]) -> IO[bytes]:
    if fmt == "gzip":
        return cast(IO[bytes], gzip.GzipFile(fileobj=stream, mode="rb"))
    if fmt == "bzip2":
        return cast(IO[bytes], bz2.BZ2File(stream, mode="rb"))
    if fmt == "xz":
        return cast(IO[bytes], lzma.LZMAFile(stream, mode="rb"))
    if fmt == "zstd" and (zstd := zstd_module()) is not None:
        return cast(IO[bytes], zstd.ZstdFile(stream, mode="rb"))
    raise ValueError(f"not a compression format: {fmt}")


def members(fmt: str, stream: IO[bytes]) -> Iterator[Member]:
    if fmt == "zip":
        return _zip_members(stream)
    if fmt == "tar":
        return _tar_members(stream)
    raise ValueError(f"not a container format: {fmt}")


def _zip_members(stream: IO[bytes]) -> Iterator[Member]:
    with zipfile.ZipFile(stream) as archive:
        for info in archive.infolist():
            unix_mode = info.external_attr >> 16 if info.create_system == 3 else 0
            encrypted = bool(info.flag_bits & 0x1)
            member = Member(
                name=info.orig_filename,  # zipfile rewrites ``filename`` per platform
                entry_type=EntryType.FILE,
                size=info.file_size,
                mode=stat.S_IMODE(unix_mode) if unix_mode else None,
                encrypted=encrypted,
            )
            if info.is_dir():
                member.entry_type = EntryType.DIRECTORY
            elif stat.S_ISLNK(unix_mode):
                member.entry_type = EntryType.SYMLINK
                if not encrypted:
                    with archive.open(info) as link:
                        member.link_target = link.read(4096).decode("utf-8", "surrogateescape")
            elif unix_mode and not stat.S_ISREG(unix_mode) and stat.S_IFMT(unix_mode):
                member.entry_type = EntryType.OTHER
            elif not encrypted:
                member.open = functools.partial(archive.open, info)
            yield member


def _tar_members(stream: IO[bytes]) -> Iterator[Member]:
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for info in archive:
            member = Member(name=info.name, entry_type=EntryType.OTHER, mode=info.mode)
            if info.isdir():
                member.entry_type = EntryType.DIRECTORY
            elif info.issym():
                member.entry_type, member.link_target = EntryType.SYMLINK, info.linkname
            elif info.islnk():
                member.entry_type, member.link_target = EntryType.HARDLINK, info.linkname
            elif info.isfile():
                member.entry_type, member.size = EntryType.FILE, info.size
                member.open = functools.partial(_extract, archive, info)
            yield member


def _extract(archive: tarfile.TarFile, info: tarfile.TarInfo) -> IO[bytes]:
    stream = archive.extractfile(info)
    if stream is None:
        raise tarfile.ReadError(f"member {info.name!r} has no content")
    return stream
