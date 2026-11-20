"""Go modules: ``go.sum``, ``vendor/modules.txt``, module cache paths and the ``h1:`` hash.

``h1:`` is Go's dirhash ``Hash1``: the sha256 of the lines ``"<sha256 hex>  <name>\\n"`` for each
file of the module zip, sorted by name, in base64. ``go.sum`` records it for every module zip and
every ``go.mod``; the go command refuses a module whose hash differs. Computed here from the zip,
without the go toolchain.
"""

import base64
import hashlib
import lzma
import re
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import BinaryIO

_SUM_LINE = re.compile(
    r"^(?P<module>\S+)\s+(?P<version>\S+?)(?P<mod>/go\.mod)?\s+(?P<hash>h1:\S+)$"
)


@dataclass(frozen=True, slots=True)
class SumEntry:
    module: str
    version: str
    go_mod: bool  # the entry is for the module's go.mod only
    hash: str


def hash1(files: Iterable[tuple[str, str]]) -> str:
    """``h1:`` over (name, sha256 hex) pairs."""
    summary = hashlib.sha256()
    for name, digest in sorted(files):
        if "\n" in name:
            raise ValueError("file names in a module may not contain newlines")
        summary.update(f"{digest}  {name}\n".encode())
    return "h1:" + base64.b64encode(summary.digest()).decode()


class ZipHashError(ValueError):
    """The zip cannot be hashed: damaged, encrypted, or larger than a module may be."""


# The go command refuses module zips over 500 MiB uncompressed; provider packages are held to
# a roomier limit by their caller.
MODULE_ZIP_LIMIT = 500 << 20
_MAX_MEMBERS = 200_000


def zip_hash(stream: BinaryIO, limit: int = MODULE_ZIP_LIMIT) -> str:
    """``h1:`` of a zip, reading each member as a stream, up to ``limit`` expanded bytes."""
    files = []
    left = limit
    try:
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            if len(members) > _MAX_MEMBERS or sum(m.file_size for m in members) > limit:
                raise ZipHashError("larger than superscrubber104 will hash")
            for info in members:
                digest = hashlib.sha256()
                with archive.open(info) as member:
                    while block := member.read(1 << 20):
                        left -= len(block)
                        if left < 0:
                            raise ZipHashError("expands beyond its declared size")
                        digest.update(block)
                files.append((info.filename, digest.hexdigest()))
        return hash1(files)
    except ZipHashError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, lzma.LZMAError, EOFError,
            OSError, RuntimeError, NotImplementedError, ValueError) as exc:  # fmt: skip
        raise ZipHashError(f"unreadable zip: {exc}") from exc


def mod_hash(data: bytes) -> str:
    """``h1:`` of a ``go.mod`` as go.sum records it (a single file named go.mod)."""
    return hash1([("go.mod", hashlib.sha256(data).hexdigest())])


def parse_go_sum(text: str) -> list[SumEntry]:
    entries = []
    for line in text.splitlines():
        if match := _SUM_LINE.match(line.strip()):
            entries.append(
                SumEntry(match["module"], match["version"], bool(match["mod"]), match["hash"])
            )
    return entries


def parse_modules_txt(text: str) -> Iterator[tuple[str, str]]:
    """(module, version) for each module ``vendor/modules.txt`` says is vendored. Modules replaced
    by a local directory are skipped: they are source in the delivery, not downloads."""
    for line in text.splitlines():
        if not line.startswith("# "):
            continue
        parts = line[2:].split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            if "=>" in parts and len(parts) == parts.index("=>") + 2:
                continue  # => ./local/path
            yield parts[0], parts[1]


def unescape(path: str) -> str:
    """Module cache paths escape upper case as ``!`` + lower case."""
    return re.sub(r"!([a-z])", lambda m: m[1].upper(), path)


def cache_entry(path: str) -> tuple[str, str, str] | None:
    """(module, version, extension) for ``.../cache/download/<module>/@v/<version>.<zip|mod>``."""
    marker = "cache/download/"
    at = path.rfind(marker)
    if at < 0 or "/@v/" not in path[at:]:
        return None
    module, _, file = path[at + len(marker) :].partition("/@v/")
    version, dot, extension = file.rpartition(".")
    if not dot or extension not in ("zip", "mod", "ziphash", "info"):
        return None
    return unescape(module), unescape(version), extension
