"""Static reader for Debian packages, ``Packages`` indexes and ``Release`` files.

A ``.deb`` is an ``ar`` archive of ``debian-binary``, ``control.tar.*`` and ``data.tar.*``. Only
the control archive is read: package identity, dependencies, and which maintainer scripts it
carries. Individual ``.deb`` files are not signed; their authenticity comes from the repository:
the signed ``InRelease``/``Release`` lists the hashes of the ``Packages`` index, which lists the
hash of every ``.deb``.

``deb_vercmp`` orders versions exactly as dpkg does.
"""

import io
import lzma
import re
import tarfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from airlock.archive import ZSTD_ADVICE, zstd_module

_AR_MAGIC = b"!<arch>\n"
_CONTROL_LIMIT = 16 << 20
SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config", "triggers")


class DebError(ValueError):
    pass


@dataclass(slots=True)
class DebPackage:
    fields: dict[str, str]
    scripts: list[str] = field(default_factory=list)
    compression: str | None = None

    @property
    def name(self) -> str:
        return self.fields.get("Package", "")

    @property
    def version(self) -> str:
        return self.fields.get("Version", "")

    @property
    def arch(self) -> str:
        return self.fields.get("Architecture", "")


def ar_members(stream: BinaryIO) -> Iterator[tuple[str, bytes | None, int]]:
    """(name, data or None when skipped, size) for each member; data only for control.tar."""
    if stream.read(8) != _AR_MAGIC:
        raise DebError("not an ar archive")
    while True:
        header = stream.read(60)
        if len(header) < 60:
            return
        if header[58:60] != b"`\n":
            raise DebError("bad ar member header")
        name = header[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii", "replace").strip() or 0)
        except ValueError as exc:
            raise DebError("bad ar member size") from exc
        if size < 0:
            raise DebError("bad ar member size")
        if name.startswith("control.tar") and size <= _CONTROL_LIMIT:
            data = stream.read(size)
            yield name, data, size
        else:
            stream.seek(size, io.SEEK_CUR)
            yield name, None, size
        if size % 2:
            stream.read(1)


def parse_fields(text: str) -> dict[str, str]:
    """One RFC 822-style stanza: continuation lines are folded into their field."""
    fields: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and key:
            fields[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            fields[key] = value.strip()
    return fields


def stanzas(text: str) -> Iterator[dict[str, str]]:
    for block in re.split(r"\n\s*\n", text):
        if block.strip():
            yield parse_fields(block)


def _decompress(name: str, data: bytes) -> bytes:
    """The control archive, expanded to at most ``_CONTROL_LIMIT`` bytes (it is untrusted input:
    a few kilobytes can claim to expand to gigabytes)."""
    try:
        if name.endswith(".gz"):
            out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, _CONTROL_LIMIT + 1)
        elif name.endswith(".xz"):
            out = lzma.LZMADecompressor().decompress(data, _CONTROL_LIMIT + 1)
        elif name.endswith(".zst"):
            zstd = zstd_module()
            if zstd is None:
                raise DebError(f"zstd-compressed control archive: {ZSTD_ADVICE}")
            out = bytes(zstd.ZstdDecompressor().decompress(data, _CONTROL_LIMIT + 1))
        else:
            out = data
    except (zlib.error, lzma.LZMAError, EOFError, OSError) as exc:
        raise DebError(f"control archive does not decompress: {exc}") from exc
    if len(out) > _CONTROL_LIMIT:
        raise DebError("control archive expands beyond the size airlock will read")
    return out


def read_deb(stream: BinaryIO) -> DebPackage:
    for name, data, _ in ar_members(stream):
        if data is None:
            continue
        raw = _decompress(name, data)
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                members = {m.name.lstrip("./"): m for m in archive.getmembers() if m.isfile()}
                control = members.get("control")
                if control is None:
                    raise DebError("control.tar has no control file")
                handle = archive.extractfile(control)
                assert handle is not None  # noqa: S101 - isfile() was checked
                fields = parse_fields(handle.read(1 << 20).decode("utf-8", "replace"))
                scripts = sorted(s for s in SCRIPTS if s in members)
        except (tarfile.TarError, EOFError) as exc:
            raise DebError(f"control archive is not a readable tar: {exc}") from exc
        return DebPackage(fields, scripts, name.rpartition(".")[2] if "." in name else None)
    raise DebError("no control archive in the package")


# --- version comparison -------------------------------------------------------------------------


def _order(char: str) -> int:
    if char == "~":
        return -1
    if char.isdigit() or not char:
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return 1 if ac > bc else -1
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = (a[i] > b[j]) - (a[i] < b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def split_version(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch) if epoch.isdigit() else 0, upstream, revision


def deb_vercmp(a: str, b: str) -> int:
    """dpkg's version comparison: -1, 0 or 1."""
    ea, ua, ra = split_version(a)
    eb, ub, rb = split_version(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return _compare_part(ua, ub) or _compare_part(ra, rb)
