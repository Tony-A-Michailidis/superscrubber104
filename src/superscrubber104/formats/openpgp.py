"""OpenPGP signatures (RFC 4880 / RFC 9580), verified natively with ``cryptography``.

Vendors sign repositories and packages with OpenPGP: AlmaLinux signs RPM headers and
``repomd.xml``; Ubuntu signs ``InRelease`` (clear-signed) and ``Release.gpg`` (detached). This
module reads public keys and signatures (armored or binary) and verifies:

* v4 keys and signatures with RSA, ECDSA (P-256/384/521), EdDSA (legacy Ed25519) and Ed25519;
* binary and canonical-text signatures, detached or clear-signed;
* hash algorithms SHA-224/256/384/512. SHA-1 and MD5 signatures are refused as too weak.

The keys are whatever the policy pins (``trust.upstream``, ``type: gpg``); every key and subkey in a
pinned file is trusted, since the file itself is pinned by hash. A signature from a key that is not
in a pinned file is never verified against anything else.
"""

import base64
import hashlib
import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

_HASHES: dict[int, tuple[str, type[hashes.HashAlgorithm]]] = {
    8: ("sha256", hashes.SHA256),
    9: ("sha384", hashes.SHA384),
    10: ("sha512", hashes.SHA512),
    11: ("sha224", hashes.SHA224),
}
_WEAK = {1: "MD5", 2: "SHA-1", 3: "RIPEMD-160"}
_CURVES = {
    bytes.fromhex("2a8648ce3d030107"): ec.SECP256R1(),
    bytes.fromhex("2b81040022"): ec.SECP384R1(),
    bytes.fromhex("2b81040023"): ec.SECP521R1(),
}
_ED25519_OID = bytes.fromhex("2b06010401da470f01")
_ARMOR = re.compile(
    rb"-----BEGIN PGP (?P<kind>[A-Z ]+)-----\r?\n(?P<body>.*?)-----END PGP (?P=kind)-----", re.S
)


class OpenPGPError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PublicKey:
    fingerprint: str  # upper-case hex, v4: 40 characters
    algorithm: int
    key: Any  # cryptography public key
    created: datetime
    subkey: bool = False

    @property
    def key_id(self) -> str:
        return self.fingerprint[-16:]


@dataclass(frozen=True, slots=True)
class Signature:
    sig_type: int
    pub_algo: int
    hash_algo: int
    hashed: bytes  # version through hashed subpackets: what the trailer covers
    left16: bytes
    values: tuple[Any, ...]  # MPIs (ints) or raw bytes, per algorithm
    created: datetime | None = None
    expires: datetime | None = None
    issuer_fingerprint: str | None = None
    issuer_key_id: str | None = None

    @property
    def issuer(self) -> str | None:
        return self.issuer_fingerprint or self.issuer_key_id


@dataclass(slots=True)
class Result:
    valid: bool
    key: PublicKey | None = None
    reason: str | None = None
    signature: Signature | None = None
    details: dict[str, Any] = field(default_factory=dict)


# --- packets ------------------------------------------------------------------------------------


def dearmor(data: bytes) -> list[tuple[str, bytes]]:
    """(kind, binary) for every armored block; binary input is returned as is."""
    blocks = []
    for match in _ARMOR.finditer(data):
        lines = match.group("body").splitlines()
        # Skip armor headers (up to the first blank line) and the CRC line.
        if b"" in [line.strip() for line in lines]:
            lines = lines[[line.strip() for line in lines].index(b"") + 1 :]
        body = b"".join(line.strip() for line in lines if not line.startswith(b"="))
        try:
            blocks.append((match.group("kind").decode(), base64.b64decode(body)))
        except ValueError as exc:
            raise OpenPGPError(f"bad armor: {exc}") from exc
    if not blocks and data[:1] and data[0] & 0x80:
        blocks.append(("BINARY", data))
    return blocks


def packets(data: bytes) -> Iterator[tuple[int, bytes]]:
    """(tag, body) for each packet."""
    pos = 0
    while pos < len(data):
        header = data[pos]
        if not header & 0x80:
            raise OpenPGPError("not an OpenPGP packet")
        pos += 1
        if header & 0x40:  # new format
            tag = header & 0x3F
            body = bytearray()
            while True:
                first = data[pos]
                if first < 192:
                    length, pos = first, pos + 1
                elif first < 224:
                    length, pos = ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
                elif first == 255:
                    length, pos = struct.unpack(">I", data[pos + 1 : pos + 5])[0], pos + 5
                else:  # partial body length
                    length, pos = 1 << (first & 0x1F), pos + 1
                    body += data[pos : pos + length]
                    pos += length
                    continue
                body += data[pos : pos + length]
                pos += length
                break
            yield tag, bytes(body)
        else:  # old format
            tag, kind = (header >> 2) & 0x0F, header & 0x03
            if kind == 3:
                length, size = len(data) - pos, 0
            else:
                size = (1, 2, 4)[kind]
                length = int.from_bytes(data[pos : pos + size], "big")
            pos += size
            yield tag, data[pos : pos + length]
            pos += length


def _mpi(data: bytes, pos: int) -> tuple[int, int]:
    bits = struct.unpack(">H", data[pos : pos + 2])[0]
    size = (bits + 7) // 8
    return int.from_bytes(data[pos + 2 : pos + 2 + size], "big"), pos + 2 + size


def _mpi_bytes(data: bytes, pos: int) -> tuple[bytes, int]:
    bits = struct.unpack(">H", data[pos : pos + 2])[0]
    size = (bits + 7) // 8
    return data[pos + 2 : pos + 2 + size], pos + 2 + size


def _public_key(body: bytes, subkey: bool) -> PublicKey | None:
    if body[0] != 4:
        return None  # v3 keys are obsolete; v6 keys are not used by the vendors here
    created = datetime.fromtimestamp(struct.unpack(">I", body[1:5])[0], UTC)
    algorithm = body[5]
    fingerprint = (
        hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body, usedforsecurity=False)
        .hexdigest()
        .upper()
    )
    pos = 6
    key: Any = None
    if algorithm in (1, 2, 3):
        n, pos = _mpi(body, pos)
        e, pos = _mpi(body, pos)
        key = rsa.RSAPublicNumbers(e, n).public_key()
    elif algorithm == 19:
        oid = body[pos + 1 : pos + 1 + body[pos]]
        point, _ = _mpi_bytes(body, pos + 1 + body[pos])
        curve = _CURVES.get(oid)
        if curve is None:
            return None
        key = ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
    elif algorithm == 22:
        oid = body[pos + 1 : pos + 1 + body[pos]]
        point, _ = _mpi_bytes(body, pos + 1 + body[pos])
        if oid != _ED25519_OID or point[:1] != b"\x40":
            return None
        key = ed25519.Ed25519PublicKey.from_public_bytes(point[1:33])
    elif algorithm == 27:
        key = ed25519.Ed25519PublicKey.from_public_bytes(body[pos : pos + 32])
    else:
        return None  # encryption-only or unsupported: never a signing key here
    return PublicKey(fingerprint, algorithm, key, created, subkey)


def load_keys(data: bytes) -> list[PublicKey]:
    """Every usable public key and subkey in a key file (armored or binary, one or more keys)."""
    keys = []
    try:
        for _, block in dearmor(data):
            for tag, body in packets(block):
                if tag in (6, 14):
                    key = _public_key(body, subkey=tag == 14)
                    if key is not None:
                        keys.append(key)
    except OpenPGPError:
        raise
    except (IndexError, struct.error, OverflowError, ValueError) as exc:
        raise OpenPGPError(f"truncated or malformed key data: {exc}") from exc
    return keys


def _subpackets(data: bytes) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos < len(data):
        first = data[pos]
        if first < 192:
            length, pos = first, pos + 1
        elif first < 255:
            length, pos = ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
        else:
            length, pos = struct.unpack(">I", data[pos + 1 : pos + 5])[0], pos + 5
        if length < 1 or pos + length > len(data):
            raise OpenPGPError("malformed signature subpacket")
        yield data[pos] & 0x7F, data[pos + 1 : pos + length]
        pos += length


def parse_signature(body: bytes) -> Signature:
    try:
        return _parse_signature(body)
    except (IndexError, struct.error, OverflowError, OSError) as exc:
        raise OpenPGPError(f"truncated or malformed signature packet: {exc}") from exc


def _parse_signature(body: bytes) -> Signature:
    if not body or body[0] != 4:
        raise OpenPGPError(f"signature version {body[0] if body else '?'} is not supported")
    sig_type, pub_algo, hash_algo = body[1], body[2], body[3]
    hashed_len = struct.unpack(">H", body[4:6])[0]
    hashed = body[: 6 + hashed_len]
    pos = 6 + hashed_len
    unhashed_len = struct.unpack(">H", body[pos : pos + 2])[0]
    unhashed = body[pos + 2 : pos + 2 + unhashed_len]
    pos += 2 + unhashed_len
    left16 = body[pos : pos + 2]
    pos += 2
    values: tuple[Any, ...]
    if pub_algo in (1, 2, 3):
        values = (_mpi(body, pos)[0],)
    elif pub_algo in (19, 22):
        r, pos = _mpi(body, pos)
        s, pos = _mpi(body, pos)
        values = (r, s)
    elif pub_algo == 27:
        values = (body[pos : pos + 64],)
    else:
        values = ()
    # Creation and expiry are only believed from the hashed area, which the signature covers:
    # the unhashed area can be rewritten by anyone, so there it may only name the issuer (a hint
    # for choosing a key, proven or not by the verification itself).
    info: dict[str, Any] = {}
    for kind, value in _subpackets(hashed[6:]):
        if kind == 2 and len(value) == 4:
            info["created"] = datetime.fromtimestamp(struct.unpack(">I", value)[0], UTC)
        elif kind == 3 and len(value) == 4:
            info["lifetime"] = struct.unpack(">I", value)[0]
    for kind, value in [*_subpackets(hashed[6:]), *_subpackets(unhashed)]:
        if kind == 16:
            info.setdefault("issuer_key_id", value.hex().upper())
        elif kind == 33:
            info.setdefault("issuer_fingerprint", value[1:].hex().upper())
    created = info.get("created")
    expires = None
    if created and info.get("lifetime"):
        expires = datetime.fromtimestamp(created.timestamp() + info["lifetime"], UTC)
    return Signature(
        sig_type, pub_algo, hash_algo, hashed, left16, values, created, expires,
        info.get("issuer_fingerprint"), info.get("issuer_key_id"),
    )  # fmt: skip


def load_signatures(data: bytes) -> list[Signature]:
    """Every signature in ``data`` this module can read. Signatures of other versions are skipped
    when a readable one is present; damaged input raises ``OpenPGPError``."""
    out = []
    unreadable: OpenPGPError | None = None
    try:
        for _, block in dearmor(data):
            for tag, body in packets(block):
                if tag != 2:
                    continue
                try:
                    out.append(parse_signature(body))
                except OpenPGPError as exc:
                    unreadable = unreadable or exc
    except (IndexError, struct.error, OverflowError) as exc:
        raise OpenPGPError(f"truncated or malformed OpenPGP data: {exc}") from exc
    if not out and unreadable is not None:
        raise unreadable
    return out


# --- verification -------------------------------------------------------------------------------


def canonical_text(data: bytes) -> bytes:
    """Text signatures: line endings as CRLF, trailing whitespace dropped per line."""
    lines = data.replace(b"\r\n", b"\n").split(b"\n")
    return b"\r\n".join(line.rstrip(b" \t\r") for line in lines)


def _digest(
    signature: Signature, chunks: Iterable[bytes]
) -> tuple[bytes, type[hashes.HashAlgorithm]]:
    name, algorithm = _HASHES[signature.hash_algo]
    digest = hashlib.new(name)
    for chunk in chunks:
        digest.update(chunk)
    digest.update(signature.hashed)
    digest.update(b"\x04\xff" + struct.pack(">I", len(signature.hashed)))
    return digest.digest(), algorithm


def _check(
    signature: Signature, key: PublicKey, digest: bytes, algorithm: type[hashes.HashAlgorithm]
) -> bool:
    try:
        if isinstance(key.key, rsa.RSAPublicKey) and signature.pub_algo in (1, 3):
            size = (key.key.key_size + 7) // 8
            key.key.verify(
                signature.values[0].to_bytes(size, "big"), digest, padding.PKCS1v15(),
                utils.Prehashed(algorithm()),
            )  # fmt: skip
            return True
        if isinstance(key.key, ec.EllipticCurvePublicKey) and signature.pub_algo == 19:
            der = utils.encode_dss_signature(*signature.values)
            key.key.verify(der, digest, ec.ECDSA(utils.Prehashed(algorithm())))
            return True
        if isinstance(key.key, ed25519.Ed25519PublicKey) and signature.pub_algo == 22:
            r, s = signature.values
            key.key.verify(r.to_bytes(32, "big") + s.to_bytes(32, "big"), digest)
            return True
        if isinstance(key.key, ed25519.Ed25519PublicKey) and signature.pub_algo == 27:
            key.key.verify(signature.values[0], digest)
            return True
    except (InvalidSignature, ValueError, OverflowError):
        return False
    return False


def verify(
    signature: Signature,
    chunks: Iterable[bytes],
    keys: Iterable[PublicKey],
    at: datetime | None = None,
) -> Result:
    """Verify one signature over the data in ``chunks`` with the first matching pinned key."""
    if signature.hash_algo in _WEAK:
        return Result(
            False,
            reason=f"{_WEAK[signature.hash_algo]} signatures are refused",
            signature=signature,
        )
    if signature.hash_algo not in _HASHES:
        return Result(
            False, reason=f"unknown hash algorithm {signature.hash_algo}", signature=signature
        )
    if signature.sig_type not in (0x00, 0x01):
        return Result(
            False,
            reason=f"signature type {signature.sig_type:#x} does not sign data",
            signature=signature,
        )
    issuer = signature.issuer
    candidates = [
        k for k in keys
        if issuer is None or k.fingerprint.endswith(issuer) or k.fingerprint == issuer
    ]  # fmt: skip
    if not candidates:
        return Result(
            False,
            reason=f"signed by key {issuer}, which no pinned key file holds",
            signature=signature,
        )
    data = chunks if signature.sig_type == 0x00 else [canonical_text(b"".join(chunks))]
    digest, algorithm = _digest(signature, data)
    if digest[:2] != signature.left16:
        return Result(False, candidates[0], "the data does not match the signature", signature)
    for key in candidates:
        if _check(signature, key, digest, algorithm):
            if at is not None and signature.expires is not None and at > signature.expires:
                return Result(False, key, "the signature has expired", signature)
            return Result(True, key, signature=signature)
    return Result(False, candidates[0], "the signature does not verify", signature)


def verify_detached(
    signature_data: bytes, data: bytes | BinaryIO, keys: Iterable[PublicKey]
) -> Result:
    """A detached signature file (``.asc``, ``.gpg``, ``.sig``) over ``data``."""
    signatures = load_signatures(signature_data)
    if not signatures:
        return Result(False, reason="no signature found")
    keys = list(keys)
    last = Result(False, reason="no signature verified")
    for signature in signatures:
        chunks = [data] if isinstance(data, bytes) else _read(data)
        result = verify(signature, chunks, keys)
        if result.valid:
            return result
        last = result
        if not isinstance(data, bytes):
            data.seek(0)
    return last


def _read(stream: BinaryIO) -> Iterator[bytes]:
    while block := stream.read(1 << 20):
        yield block


def verify_clearsigned(data: bytes, keys: Iterable[PublicKey]) -> tuple[Result, bytes]:
    """A clear-signed document (``InRelease``). Returns the result and the signed text."""
    head = b"-----BEGIN PGP SIGNED MESSAGE-----"
    start = data.find(head)
    # At the start of a line: the same words inside the text are dash-escaped ("- -----BEGIN").
    sig_at = data.find(b"\n-----BEGIN PGP SIGNATURE-----", max(start, 0))
    if start < 0 or sig_at < 0:
        return Result(False, reason="not a clear-signed document"), b""
    sig_at += 1
    lines = data[start + len(head) :].split(b"\n")[1:]
    # Armor headers ("Hash: SHA512") end at the first empty line; the text runs up to the
    # signature, and the line break just before the signature belongs to the signature.
    first = next((i for i, line in enumerate(lines) if not line.strip(b"\r")), len(lines))
    text: list[bytes] = []
    for line in lines[first + 1 :]:
        if line.startswith(b"-----BEGIN PGP SIGNATURE-----"):
            break
        line = line.rstrip(b"\r")
        text.append(line[2:] if line.startswith(b"- ") else line)
    signed = b"\n".join(text)
    try:
        signatures = load_signatures(data[sig_at:])
    except OpenPGPError as exc:
        return Result(False, reason=f"unreadable signature: {exc}"), signed
    keys = list(keys)
    last = Result(False, reason="no signature found")
    for signature in signatures:
        result = verify(signature, [signed], keys)
        if result.valid:
            return result, signed
        last = result
    return last, signed
