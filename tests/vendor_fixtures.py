"""Synthetic vendor artefacts: OpenPGP keys and signatures, RPM and Debian packages, RPM databases.

Everything is generated here from fresh keys, so no vendor material is in the repository. The
readers these exercise were also checked against real AlmaLinux and Ubuntu packages, repository
metadata and archive keys.
"""

import base64
import gzip
import hashlib
import io
import sqlite3
import struct
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils

from airlock.formats.openpgp import canonical_text

CREATED = 1_700_000_000  # 2023-11-14, before the tests' NOW
_HASH = {8: ("sha256", hashes.SHA256), 10: ("sha512", hashes.SHA512), 2: ("sha1", hashes.SHA1)}


def packet(tag: int, body: bytes) -> bytes:
    """A new-format OpenPGP packet with a five-octet length."""
    return bytes([0xC0 | tag, 255]) + struct.pack(">I", len(body)) + body


def _mpi(value: int) -> bytes:
    return struct.pack(">H", value.bit_length()) + value.to_bytes((value.bit_length() + 7) // 8)


def armor(kind: str, data: bytes) -> bytes:
    text = base64.b64encode(data).decode()
    lines = [text[i : i + 64] for i in range(0, len(text), 64)]
    return (
        f"-----BEGIN PGP {kind}-----\n\n" + "\n".join(lines) + f"\n-----END PGP {kind}-----\n"
    ).encode()


@dataclass
class PGPKey:
    """A v4 signing key: RSA (as the RPM vendors use) or Ed25519."""

    algorithm: str = "ed25519"
    private: object = field(init=False)

    def __post_init__(self) -> None:
        if self.algorithm == "rsa":
            self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            self.private = ed25519.Ed25519PrivateKey.generate()

    @property
    def body(self) -> bytes:
        head = b"\x04" + struct.pack(">I", CREATED)
        if isinstance(self.private, rsa.RSAPrivateKey):
            numbers = self.private.public_key().public_numbers()
            return head + b"\x01" + _mpi(numbers.n) + _mpi(numbers.e)
        assert isinstance(self.private, ed25519.Ed25519PrivateKey)
        return head + bytes([27]) + self.private.public_key().public_bytes_raw()

    @property
    def fingerprint(self) -> bytes:
        body = self.body
        return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()  # noqa: S324

    def public(self, *, armored: bool = True) -> bytes:
        data = packet(6, self.body)
        return armor("PUBLIC KEY BLOCK", data) if armored else data

    def sign(self, data: bytes, *, sig_type: int = 0x00, hash_algo: int = 8) -> bytes:
        """A binary signature packet over ``data``."""
        algo = 1 if isinstance(self.private, rsa.RSAPrivateKey) else 27
        subpackets = (
            bytes([5, 2]) + struct.pack(">I", CREATED + 60)
            + bytes([22, 33, 4]) + self.fingerprint
        )  # fmt: skip
        hashed = bytes([4, sig_type, algo, hash_algo]) + struct.pack(">H", len(subpackets))
        hashed += subpackets
        name, algorithm = _HASH[hash_algo]
        signed = canonical_text(data) if sig_type == 0x01 else data
        digest = hashlib.new(name, signed + hashed + b"\x04\xff" + struct.pack(">I", len(hashed)))
        value = digest.digest()
        if isinstance(self.private, rsa.RSAPrivateKey):
            raw = self.private.sign(value, padding.PKCS1v15(), utils.Prehashed(algorithm()))
            material = _mpi(int.from_bytes(raw))
        else:
            assert isinstance(self.private, ed25519.Ed25519PrivateKey)
            material = self.private.sign(value)
        unhashed = bytes([9, 16]) + self.fingerprint[-8:]
        body = hashed + struct.pack(">H", len(unhashed)) + unhashed + value[:2] + material
        return packet(2, body)

    def detached(self, data: bytes, *, armored: bool = True, hash_algo: int = 8) -> bytes:
        signature = self.sign(data, hash_algo=hash_algo)
        return armor("SIGNATURE", signature) if armored else signature

    def clearsign(self, text: str) -> bytes:
        """A clear-signed document, as ``InRelease`` or Fedora's ``CHECKSUM`` files are."""
        body = text.rstrip("\n")
        escaped = "\n".join(
            ("- " + line) if line.startswith("-") else line for line in body.split("\n")
        )
        signature = self.sign(body.encode(), sig_type=0x01)
        return (
            b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            + escaped.encode()
            + b"\n"
            + armor("SIGNATURE", signature)
        )


# --- RPM ----------------------------------------------------------------------------------------

_STRING, _STRING_ARRAY, _INT32, _BIN = 6, 8, 4, 7


def rpm_header(entries: Mapping[int, tuple[int, object]], *, magic: bool = True) -> bytes:
    """An RPM header: ``{tag: (type, value)}``. Without ``magic`` it is what rpmdb stores."""
    index, store = b"", b""
    for tag, (kind, value) in sorted(entries.items()):
        if kind == _INT32:
            assert isinstance(value, list)
            store += b"\x00" * (-len(store) % 4)
            data, count = b"".join(struct.pack(">i", v) for v in value), len(value)
        elif kind == _STRING:
            data, count = str(value).encode() + b"\x00", 1
        elif kind == _STRING_ARRAY:
            assert isinstance(value, list)
            data, count = b"".join(v.encode() + b"\x00" for v in value), len(value)
        else:
            assert isinstance(value, bytes)
            data, count = value, len(value)
        index += struct.pack(">iiii", tag, kind, len(store), count)
        store += data
    sizes = struct.pack(">II", len(entries), len(store))
    return (b"\x8e\xad\xe8\x01\x00\x00\x00\x00" if magic else b"") + sizes + index + store


@dataclass
class RPMSpec:
    name: str = "tinytool"
    version: str = "1.2"
    release: str = "3.el9"
    arch: str = "x86_64"
    vendor: str = "Example Linux"
    licence: str = "MIT"
    epoch: int | None = None
    postin: str | None = "/sbin/ldconfig"
    payload: bytes = b"compressed payload stands in here"

    def main(self) -> dict[int, tuple[int, object]]:
        entries: dict[int, tuple[int, object]] = {
            1000: (_STRING, self.name),
            1001: (_STRING, self.version),
            1002: (_STRING, self.release),
            1004: (_STRING, "a tiny tool"),
            1011: (_STRING, self.vendor),
            1014: (_STRING, self.licence),
            1022: (_STRING, self.arch),
            1044: (_STRING, f"{self.name}-{self.version}-{self.release}.src.rpm"),
            1047: (_STRING_ARRAY, [self.name]),
            1049: (_STRING_ARRAY, ["libc.so.6()(64bit)"]),
            5092: (_STRING_ARRAY, [hashlib.sha256(self.payload).hexdigest()]),
            5093: (_INT32, [8]),
        }
        if self.epoch is not None:
            entries[1003] = (_INT32, [self.epoch])
        if self.postin:
            entries[1024] = (_STRING, self.postin)
        return entries


def rpm_bytes(
    spec: RPMSpec | None = None, key: PGPKey | None = None, *, payload: bytes | None = None
) -> bytes:
    """A complete .rpm. ``payload`` replaces the payload after the header is written (tampering)."""
    spec = spec or RPMSpec()
    main = rpm_header(spec.main())
    signature: dict[int, tuple[int, object]] = {273: (_STRING, hashlib.sha256(main).hexdigest())}
    if key is not None:
        signature[268] = (_BIN, key.sign(main))
    sig_header = rpm_header(signature)
    sig_header += b"\x00" * (-len(sig_header) % 8)
    lead = b"\xed\xab\xee\xdb\x03\x00\x00\x00" + b"\x00" * 88
    return lead + sig_header + main + (spec.payload if payload is None else payload)


def rpmdb_bytes(specs: list[RPMSpec], tmp: Path) -> bytes:
    """An ``rpmdb.sqlite`` as rpm 4.16+ writes it: header blobs in a ``Packages`` table."""
    path = tmp / "rpmdb.sqlite"
    path.unlink(missing_ok=True)
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)"
    )
    pubkey = RPMSpec(name="gpg-pubkey", version="deadbeef", release="1", arch="")
    for spec in [*specs, pubkey]:
        con.execute(
            "INSERT INTO Packages (blob) VALUES (?)", (rpm_header(spec.main(), magic=False),)
        )
    con.commit()
    con.close()
    return path.read_bytes()


# --- Debian -------------------------------------------------------------------------------------


def _tar_gz(files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size, info.mode = len(data), 0o755
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


def _ar(members: Mapping[str, bytes]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members.items():
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
        out += header + data + (b"\n" if len(data) % 2 else b"")
    return out


def deb_bytes(
    name: str = "hello",
    version: str = "2.10-3",
    arch: str = "amd64",
    *,
    scripts: Mapping[str, bytes] | None = None,
    control: bool = True,
) -> bytes:
    fields = (
        f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n"
        "Maintainer: Example <maint@example.org>\nDepends: libc6 (>= 2.34)\n"
        "Description: says hello\n a longer description\n"
    )
    files = {
        "control": fields.encode(),
        **(scripts if scripts is not None else {"postinst": b"#!/bin/sh\n"}),
    }
    members = {"debian-binary": b"2.0\n"}
    if control:
        members["control.tar.gz"] = _tar_gz(files)
    members["data.tar.gz"] = _tar_gz({"usr/bin/hello": b"\x7fELF"})
    return _ar(members)


# --- repository metadata ------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def primary_xml(packages: Mapping[str, tuple[str, bytes]]) -> bytes:
    """``primary.xml`` listing ``{href: (name, content)}``; content is what the hash is taken of."""
    body = "".join(
        f'<package type="rpm"><name>{name}</name><arch>x86_64</arch>'
        f'<version epoch="0" ver="1.0" rel="1.el9"/>'
        f'<checksum type="sha256" pkgid="YES">{sha256_hex(data)}</checksum>'
        f'<size package="{len(data)}"/><location href="{href}"/></package>'
        for href, (name, data) in packages.items()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<metadata xmlns="http://linux.duke.edu/metadata/common" '
        f'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="{len(packages)}">'
        f"{body}</metadata>"
    ).encode()


def repomd_xml(data: Mapping[str, tuple[str, bytes]], timestamp: int = CREATED) -> bytes:
    """``repomd.xml`` listing ``{type: (href, content)}``."""
    body = "".join(
        f'<data type="{kind}"><checksum type="sha256">{sha256_hex(content)}</checksum>'
        f'<location href="{href}"/><timestamp>{timestamp}</timestamp>'
        f"<size>{len(content)}</size></data>"
        for kind, (href, content) in data.items()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo">'
        f"<revision>{timestamp}</revision>{body}</repomd>"
    ).encode()


def packages_index(debs: Mapping[str, tuple[str, str, bytes]]) -> str:
    """apt ``Packages`` for ``{Filename: (package, version, content)}``."""
    return "\n".join(
        f"Package: {name}\nVersion: {version}\nArchitecture: amd64\nFilename: {filename}\n"
        f"Size: {len(data)}\nSHA256: {sha256_hex(data)}\nDescription: test\n"
        for filename, (name, version, data) in debs.items()
    )


def release_text(
    files: Mapping[str, bytes], *, date: str, valid_until: str | None = None, suite: str = "stable"
) -> str:
    """An apt ``Release`` listing ``{path below dists/<suite>/: content}``."""
    lines = [
        "Origin: Example",
        "Label: Example",
        f"Suite: {suite}",
        f"Codename: {suite}",
        f"Date: {date}",
        *([f"Valid-Until: {valid_until}"] if valid_until else []),
        "Architectures: amd64",
        "Components: main",
        "SHA256:",
        *(f" {sha256_hex(data)} {len(data):>8} {path}" for path, data in files.items()),
    ]
    return "\n".join(lines) + "\n"
