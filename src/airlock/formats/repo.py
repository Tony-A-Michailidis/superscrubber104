"""Static readers for package repository metadata: dnf/yum, apt, PyPI simple, npm and Helm.

Each reader turns an index into the same shape: the files it lists, with the hash it records for
each, relative to a base directory. Nothing is fetched, nothing is executed; large indexes
(AppStream's ``primary.xml`` is hundreds of megabytes) are read as a stream.
"""

import bz2
import gzip
import json
import lzma
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import IO, Any, BinaryIO
from urllib.parse import unquote, urlsplit

from airlock.archive import capped
from airlock.formats.deb import parse_fields

_REPO_NS = "{http://linux.duke.edu/metadata/repo}"
_COMMON_NS = "{http://linux.duke.edu/metadata/common}"
_ALGORITHMS = {"sha": "sha1", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256",
               "sha384": "sha384", "sha512": "sha512", "md5": "md5"}  # fmt: skip


class RepoError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Listed:
    """One file an index lists: where (relative to the index's base) and its recorded hash."""

    href: str
    algorithm: str | None  # hashlib name; None when the index records no hash
    digest: str | None
    size: int | None = None
    name: str | None = None  # package name, when the index says
    version: str | None = None
    external: bool = False  # an absolute URL: the content is somewhere on the network


def _algorithm(name: str | None) -> str | None:
    return _ALGORITHMS.get((name or "").lower().replace("-", ""))


# AlmaLinux AppStream's primary.xml is about 400 MiB expanded; nothing legitimate is near this.
INDEX_LIMIT = 8 << 30


def open_compressed(name: str, stream: BinaryIO, limit: int = INDEX_LIMIT) -> IO[bytes]:
    """A decompressing stream chosen by file name (gz, xz, bz2, zst on Python 3.14+, or plain),
    refusing to expand beyond ``limit`` bytes."""
    return capped(_decompressing(name, stream), limit)


def _decompressing(name: str, stream: BinaryIO) -> IO[bytes]:
    if name.endswith(".gz"):
        return gzip.GzipFile(fileobj=stream)  # type: ignore[return-value]
    if name.endswith(".xz"):
        return lzma.LZMAFile(stream)
    if name.endswith(".bz2"):
        return bz2.BZ2File(stream)
    if name.endswith(".zst"):
        try:
            from compression import zstd  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RepoError(
                "zstd-compressed metadata needs Python 3.14 (compression.zstd)"
            ) from exc
        return zstd.ZstdFile(stream)  # type: ignore[no-any-return]
    return stream


# --- dnf / yum ----------------------------------------------------------------------------------


@dataclass(slots=True)
class RepoMd:
    revision: str | None
    data: dict[str, Listed]  # by type: primary, filelists, updateinfo, modules, ...
    timestamp: int | None  # newest data timestamp


def parse_repomd(data: bytes) -> RepoMd:
    try:
        root = ET.fromstring(data)  # noqa: S314 - see the import
    except ET.ParseError as exc:
        raise RepoError(f"repomd.xml: {exc}") from exc
    if root.tag != f"{_REPO_NS}repomd":
        raise RepoError("not a repomd.xml")
    entries: dict[str, Listed] = {}
    stamps = []
    for item in root.findall(f"{_REPO_NS}data"):
        location = item.find(f"{_REPO_NS}location")
        checksum = item.find(f"{_REPO_NS}checksum")
        size = item.findtext(f"{_REPO_NS}size")
        stamp = item.findtext(f"{_REPO_NS}timestamp")
        if stamp and stamp.strip().isdigit():
            stamps.append(int(stamp))
        if location is None or not location.get("href"):
            continue
        entries[item.get("type", "")] = Listed(
            href=location.get("href", ""),
            algorithm=_algorithm(checksum.get("type")) if checksum is not None else None,
            digest=(checksum.text or "").strip().lower() if checksum is not None else None,
            size=int(size) if size and size.isdigit() else None,
        )
    revision = root.findtext(f"{_REPO_NS}revision")
    return RepoMd(revision.strip() if revision else None, entries, max(stamps, default=None))


def iter_primary(stream: IO[bytes]) -> Iterator[Listed]:
    """Every package in a ``primary.xml``, streamed: memory stays flat whatever its size."""
    try:
        for _, element in ET.iterparse(stream, events=("end",)):  # noqa: S314
            if element.tag != f"{_COMMON_NS}package":
                continue
            if element.get("type") == "rpm":
                version = element.find(f"{_COMMON_NS}version")
                checksum = element.find(f"{_COMMON_NS}checksum")
                location = element.find(f"{_COMMON_NS}location")
                size = element.find(f"{_COMMON_NS}size")
                evr = None
                if version is not None:
                    epoch = version.get("epoch", "0")
                    evr = f"{epoch + ':' if epoch not in ('', '0') else ''}"
                    evr += f"{version.get('ver', '')}-{version.get('rel', '')}"
                if location is not None and location.get("href"):
                    yield Listed(
                        href=location.get("href", ""),
                        algorithm=_algorithm(checksum.get("type"))
                        if checksum is not None
                        else None,
                        digest=(checksum.text or "").strip().lower()
                        if checksum is not None
                        else None,
                        size=_int(size.get("package")) if size is not None else None,
                        name=element.findtext(f"{_COMMON_NS}name"),
                        version=evr,
                    )
            element.clear()
    except ET.ParseError as exc:
        raise RepoError(f"primary.xml: {exc}") from exc


def _int(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


# --- apt ----------------------------------------------------------------------------------------


@dataclass(slots=True)
class Release:
    fields: dict[str, str]
    files: dict[str, Listed]  # path relative to dists/<suite>/ -> strongest hash listed
    date: datetime | None
    valid_until: datetime | None

    @property
    def identity(self) -> str:
        origin = self.fields.get("Origin", "")
        suite = self.fields.get("Suite") or self.fields.get("Codename", "")
        return f"{origin}/{suite}"


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_release(text: str) -> Release:
    fields = parse_fields(text)
    files: dict[str, Listed] = {}
    for key, algorithm in (
        ("MD5Sum", "md5"),
        ("SHA1", "sha1"),
        ("SHA256", "sha256"),
        ("SHA512", "sha512"),
    ):
        for line in fields.get(key, "").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1].isdigit():
                files[parts[2]] = Listed(parts[2], algorithm, parts[0].lower(), int(parts[1]))
    return Release(fields, files, _date(fields.get("Date")), _date(fields.get("Valid-Until")))


_DEB_HASHES = (("SHA512", "sha512"), ("SHA256", "sha256"), ("SHA1", "sha1"), ("MD5sum", "md5"))


def _stanzas(lines: Iterable[str]) -> Iterator[dict[str, str]]:
    block: list[str] = []
    for line in lines:
        if line.strip():
            block.append(line)
        elif block:
            yield parse_fields("".join(block))
            block = []
    if block:
        yield parse_fields("".join(block))


def iter_packages(lines: Iterable[str]) -> Iterator[Listed]:
    """Every stanza of an apt ``Packages`` index, streamed line by line. Filenames are relative to
    the archive root."""
    for stanza in _stanzas(lines):
        filename = stanza.get("Filename")
        if not filename:
            continue
        key, algorithm = next(((k, a) for k, a in _DEB_HASHES if stanza.get(k)), ("", None))
        yield Listed(
            href=filename,
            algorithm=algorithm,
            digest=stanza.get(key, "").lower() or None,
            size=_int(stanza.get("Size")),
            name=stanza.get("Package"),
            version=stanza.get("Version"),
        )


# --- PyPI simple (PEP 503 HTML, PEP 691 JSON) ---------------------------------------------------


class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.append({k: v or "" for k, v in attrs})


def _from_url(url: str, digests: dict[str, str]) -> Listed:
    parts = urlsplit(url)
    external = bool(parts.scheme or parts.netloc)
    if parts.fragment and "=" in parts.fragment and not digests:
        name, _, value = parts.fragment.partition("=")
        digests = {name: value}
    algorithm = next(
        (a for a in ("sha256", "sha512", "sha384", "sha1", "md5") if a in digests), None
    )
    return Listed(
        href=unquote(parts.path) if not external else url,
        algorithm=algorithm,
        digest=digests[algorithm].lower() if algorithm else None,
        external=external,
    )


def parse_simple(data: bytes) -> list[Listed]:
    """A project page of a PyPI simple index, HTML or JSON."""
    text = data.decode("utf-8", "replace")
    if text.lstrip().startswith("{"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RepoError(f"simple index: {exc}") from exc
        files = document.get("files") if isinstance(document, dict) else None
        return [
            _from_url(str(f.get("url", "")), dict(f.get("hashes") or {}))
            for f in files or []
            if isinstance(f, dict) and f.get("url")
        ]
    parser = _Anchors()
    parser.feed(text)
    return [_from_url(link["href"], {}) for link in parser.links if link.get("href")]


# --- npm (registry packuments, as Verdaccio and similar store them) -----------------------------


def is_packument(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and isinstance(document.get("versions"), dict)
        and isinstance(document.get("name"), str)
        and ("dist-tags" in document or "_id" in document)
    )


def iter_packument(document: dict[str, Any]) -> Iterator[Listed]:
    for version, meta in sorted(document.get("versions", {}).items()):
        dist = meta.get("dist") if isinstance(meta, dict) else None
        if not isinstance(dist, dict) or not dist.get("tarball"):
            continue
        algorithm, digest = None, None
        integrity = str(dist.get("integrity") or "")
        if integrity:
            algo, _, value = integrity.split()[0].partition("-")
            algorithm, digest = _algorithm(algo), value  # base64, as SRI writes it
        elif dist.get("shasum"):
            algorithm, digest = "sha1", str(dist["shasum"]).lower()
        url = str(dist["tarball"])
        yield Listed(
            href=url.rsplit("/", 1)[-1],
            algorithm=algorithm,
            digest=digest,
            name=document.get("name"),
            version=version,
        )


# --- Helm ---------------------------------------------------------------------------------------


@dataclass(slots=True)
class HelmIndex:
    generated: datetime | None
    charts: list[Listed] = field(default_factory=list)


def parse_helm_index(document: Any) -> HelmIndex:
    if not isinstance(document, dict) or not isinstance(document.get("entries"), dict):
        raise RepoError("not a Helm repository index")
    charts = []
    for name, versions in sorted(document["entries"].items()):
        for entry in versions if isinstance(versions, list) else []:
            if not isinstance(entry, dict):
                continue
            urls = [str(u) for u in entry.get("urls") or []]
            if not urls:
                continue
            parts = urlsplit(urls[0])
            external = bool(parts.scheme or parts.netloc)
            digest = str(entry.get("digest") or "").lower() or None
            charts.append(
                Listed(
                    href=parts.path.rsplit("/", 1)[-1] if external else unquote(parts.path),
                    algorithm="sha256" if digest else None,
                    digest=digest,
                    name=str(name),
                    version=str(entry.get("version", "")),
                )
            )
    generated = document.get("generated")
    when = None
    if isinstance(generated, datetime):
        when = generated if generated.tzinfo else generated.replace(tzinfo=UTC)
    elif isinstance(generated, str):
        try:
            when = datetime.fromisoformat(generated.replace("Z", "+00:00"))
        except ValueError:
            when = None
    return HelmIndex(when, charts)


_PROV_FILE = re.compile(r"^\s+(?P<name>[^:\s]+\.tgz):\s*sha256:(?P<hash>[0-9a-fA-F]{64})\s*$", re.M)


def provenance_files(text: str) -> dict[str, str]:
    """The ``files:`` section of a Helm ``.prov`` body: chart archive name -> sha256."""
    return {m["name"]: m["hash"].lower() for m in _PROV_FILE.finditer(text)}
