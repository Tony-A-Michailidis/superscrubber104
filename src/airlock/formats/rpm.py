"""Static reader for RPM packages (v4): identity, scriptlets, digests and the header signature.

An RPM is a lead, a signature header, the main header, and the compressed payload. The vendor's
OpenPGP signature (``RSAHEADER``, tag 268) covers the main header, and the main header holds the
payload's digest (``PAYLOADDIGEST``, tag 5092), so a verified header signature plus a matching
payload digest proves the whole package. Nothing is installed, extracted or run.

``rpm_vercmp`` and ``compare_evr`` order versions exactly as rpm does.
"""

import hashlib
import re
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

LEAD = 96
_LEAD_MAGIC = b"\xed\xab\xee\xdb"
_HEADER_MAGIC = b"\x8e\xad\xe8\x01"
_MAX_HEADER = 64 << 20

# Main header tags
NAME, VERSION, RELEASE, EPOCH, SUMMARY, LICENSE, ARCH = 1000, 1001, 1002, 1003, 1004, 1014, 1022
SOURCERPM, VENDOR, PAYLOADDIGEST, PAYLOADDIGESTALGO = 1044, 1011, 5092, 5093
REQUIRENAME, REQUIREVERSION, PROVIDENAME, PROVIDEVERSION = 1049, 1050, 1047, 1113
SCRIPTLETS = {1023: "prein", 1024: "postin", 1025: "preun", 1026: "postun",
              1151: "pretrans", 1152: "posttrans", 1065: "triggerscripts"}  # fmt: skip
# Signature header tags
SIG_SIZE, SIG_RSAHEADER, SIG_SHA1HEADER, SIG_SHA256HEADER, SIG_PGP = 1000, 268, 269, 273, 1002
_DIGEST_ALGOS = {8: "sha256", 9: "sha384", 10: "sha512", 2: "sha1"}


class RPMError(ValueError):
    pass


@dataclass(slots=True)
class Header:
    tags: dict[int, object]
    raw: bytes  # the header exactly as stored: what the header signature covers


@dataclass(slots=True)
class Package:
    name: str
    version: str
    release: str
    epoch: int | None
    arch: str
    summary: str | None
    licence: str | None
    vendor: str | None
    source_rpm: str | None
    scriptlets: list[str]
    requires: list[str]
    provides: list[str]
    signature: bytes | None  # the OpenPGP signature packet over the main header
    header: bytes
    header_sha256: str | None  # as recorded in the signature header
    payload_digest: tuple[str, str] | None  # (algorithm, hex) recorded in the main header
    problems: list[str] = field(default_factory=list)

    @property
    def evr(self) -> str:
        epoch = f"{self.epoch}:" if self.epoch else ""
        return f"{epoch}{self.version}-{self.release}"


def _header(stream: "BinaryIO | _Bytes", pad: bool) -> Header:
    intro = stream.read(16)
    if len(intro) < 16 or intro[:4] != _HEADER_MAGIC:
        raise RPMError("no RPM header where one should be")
    count, store_size = struct.unpack(">II", intro[8:16])
    size = count * 16 + store_size
    if size > _MAX_HEADER:
        raise RPMError("RPM header is implausibly large")
    body = stream.read(size)
    if len(body) < size:
        raise RPMError("RPM header is truncated")
    if pad and size % 8:
        stream.read(8 - size % 8)
    store = body[count * 16 :]
    tags: dict[int, object] = {}
    for i in range(count):
        tag, kind, offset, n = struct.unpack(">iiii", body[i * 16 : i * 16 + 16])
        if not 0 <= offset <= len(store):
            continue
        if kind == 4:  # INT32
            tags[tag] = list(struct.unpack(f">{n}i", store[offset : offset + 4 * n]))
        elif kind in (6, 9):  # STRING, I18NSTRING (first)
            tags[tag] = store[offset : store.index(b"\x00", offset)].decode("utf-8", "replace")
        elif kind == 8:  # STRING_ARRAY
            values, pos = [], offset
            for _ in range(n):
                end = store.index(b"\x00", pos)
                values.append(store[pos:end].decode("utf-8", "replace"))
                pos = end + 1
            tags[tag] = values
        elif kind == 7:  # BIN
            tags[tag] = store[offset : offset + n]
    return Header(tags, intro + body)


def read_header_blob(blob: bytes) -> dict[int, object]:
    """A header as rpm's database stores it: the index and store without the magic."""
    return _header(_Bytes(_HEADER_MAGIC + b"\x00" * 4 + blob), pad=False).tags


class _Bytes:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def read(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk


def identity(tags: dict[int, object]) -> tuple[str, str, str, int | None]:
    """(name, version-release, arch, epoch) from header tags."""
    epoch = tags.get(EPOCH)
    return (
        _str(tags, NAME) or "",
        f"{_str(tags, VERSION) or ''}-{_str(tags, RELEASE) or ''}",
        _str(tags, ARCH) or "",
        epoch[0] if isinstance(epoch, list) and epoch else None,
    )


def _str(tags: dict[int, object], tag: int) -> str | None:
    value = tags.get(tag)
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, str) else None


def _strings(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def read_package(stream: BinaryIO, *, check_payload: bool = True) -> Package:
    lead = stream.read(LEAD)
    if len(lead) < LEAD or lead[:4] != _LEAD_MAGIC:
        raise RPMError("not an RPM package (no lead)")
    signature = _header(stream, pad=True)
    main = _header(stream, pad=False)
    tags = main.tags
    epoch = tags.get(EPOCH)
    algo_tag = tags.get(PAYLOADDIGESTALGO)
    digest_value = tags.get(PAYLOADDIGEST)
    payload_digest = None
    if isinstance(digest_value, list) and digest_value:
        algo = algo_tag[0] if isinstance(algo_tag, list) and algo_tag else 8
        payload_digest = (_DIGEST_ALGOS.get(int(algo), f"algorithm-{algo}"), str(digest_value[0]))
    package = Package(
        name=_str(tags, NAME) or "",
        version=_str(tags, VERSION) or "",
        release=_str(tags, RELEASE) or "",
        epoch=epoch[0] if isinstance(epoch, list) and epoch else None,
        arch=_str(tags, ARCH) or "",
        summary=_str(tags, SUMMARY),
        licence=_str(tags, LICENSE),
        vendor=_str(tags, VENDOR),
        source_rpm=_str(tags, SOURCERPM),
        scriptlets=sorted(name for tag, name in SCRIPTLETS.items() if tags.get(tag)),
        requires=_strings(tags.get(REQUIRENAME)),
        provides=_strings(tags.get(PROVIDENAME)),
        signature=_bin(signature.tags.get(SIG_RSAHEADER)),
        header=main.raw,
        header_sha256=_str(signature.tags, SIG_SHA256HEADER),
        payload_digest=payload_digest,
    )
    if package.header_sha256 and hashlib.sha256(main.raw).hexdigest() != package.header_sha256:
        package.problems.append("the header does not match its SHA-256 digest")
    if check_payload and payload_digest and payload_digest[0] in hashlib.algorithms_available:
        digest = hashlib.new(payload_digest[0])
        while block := stream.read(1 << 20):
            digest.update(block)
        if digest.hexdigest() != payload_digest[1]:
            package.problems.append("the payload does not match the digest in the header")
    return package


def _bin(value: object) -> bytes | None:
    return value if isinstance(value, bytes) else None


# --- version comparison -------------------------------------------------------------------------

_SEGMENT = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def rpm_vercmp(a: str, b: str) -> int:
    """rpm's version comparison (rpmvercmp): -1, 0 or 1."""
    if a == b:
        return 0
    sa, sb = _SEGMENT.findall(a), _SEGMENT.findall(b)
    while sa or sb:
        if (sa and sa[0] == "~") or (sb and sb[0] == "~"):
            if not (sa and sa[0] == "~"):
                return 1
            if not (sb and sb[0] == "~"):
                return -1
            sa, sb = sa[1:], sb[1:]
            continue
        if (sa and sa[0] == "^") or (sb and sb[0] == "^"):
            if not sa:
                return -1
            if not sb:
                return 1
            if sa[0] != "^":
                return 1
            if sb[0] != "^":
                return -1
            sa, sb = sa[1:], sb[1:]
            continue
        if not sa or not sb:
            return 1 if sa else -1
        x, y = sa.pop(0), sb.pop(0)
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return 1 if xi > yi else -1
        elif x.isdigit():
            return 1
        elif y.isdigit():
            return -1
        elif x != y:
            return 1 if x > y else -1
    return 0


def split_evr(evr: str) -> tuple[int, str, str]:
    epoch, _, rest = evr.rpartition(":")
    version, _, release = rest.partition("-")
    return int(epoch) if epoch.isdigit() else 0, version, release


def compare_evr(a: str, b: str) -> int:
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return rpm_vercmp(va, vb) or (rpm_vercmp(ra, rb) if ra and rb else 0)
