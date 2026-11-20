"""Ed25519 keys and DSSE envelopes (https://github.com/secure-systems-lab/dsse).

A key id is ``ed25519:<sha256 of the raw public key>`` in full, never truncated: it is the handle
that policies, waivers and approval quorums refer to.
"""

import base64
import contextlib
import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from superscrubber104.core.canonical import JSON
from superscrubber104.core.errors import Superscrubber104Error

ALGORITHM = "ed25519"


class SigningError(Superscrubber104Error):
    """A key or signature envelope could not be loaded or parsed."""


class Signer(Protocol):
    """Anything that can sign: a key file today, a hardware token later."""

    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> bytes: ...


def _key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"{ALGORITHM}:{hashlib.sha256(raw).hexdigest()}"


@dataclass(frozen=True, slots=True)
class VerifyKey:
    public: Ed25519PublicKey
    key_id: str

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public.verify(signature, data)
        except InvalidSignature:
            return False
        return True

    def pem(self) -> bytes:
        return self.public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


@dataclass(frozen=True, slots=True)
class SigningKey:
    private: Ed25519PrivateKey
    key_id: str

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)

    @property
    def verify_key(self) -> VerifyKey:
        return VerifyKey(self.private.public_key(), self.key_id)

    def pem(self, passphrase: bytes | None = None) -> bytes:
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        return self.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )


def generate_key() -> SigningKey:
    private = Ed25519PrivateKey.generate()
    return SigningKey(private, _key_id(private.public_key()))


def save_key(
    key: SigningKey, private_path: Path, public_path: Path, passphrase: bytes | None
) -> None:
    """Write a key pair. Refuses to overwrite; the private key is created owner-only."""
    for path in (private_path, public_path):
        if path.exists():
            raise SigningError(f"refusing to overwrite {path}")
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.pem(passphrase))
    public_path.write_bytes(key.verify_key.pem())


def load_signing_key(path: Path, passphrase: bytes | None = None) -> SigningKey:
    try:
        private = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise SigningError(f"{path}: only Ed25519 keys are supported")
    return SigningKey(private, _key_id(private.public_key()))


def load_verify_key(source: Path | bytes) -> VerifyKey:
    name = str(source) if isinstance(source, Path) else "public key"
    try:
        data = source.read_bytes() if isinstance(source, Path) else source
        public = serialization.load_pem_public_key(data)
    except (OSError, ValueError) as exc:
        raise SigningError(f"cannot load {name}: {exc}") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise SigningError(f"{name}: only Ed25519 keys are supported")
    return VerifyKey(public, _key_id(public))


# --- DSSE ---------------------------------------------------------------------------------------


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding: what is actually signed."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(kind), kind, len(payload), payload)


@dataclass(frozen=True, slots=True)
class Signature:
    key_id: str
    sig: bytes


@dataclass(frozen=True, slots=True)
class Envelope:
    payload_type: str
    payload: bytes
    signatures: tuple[Signature, ...]

    def to_data(self) -> JSON:
        return {
            "payloadType": self.payload_type,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "signatures": [
                {"keyid": s.key_id, "sig": base64.b64encode(s.sig).decode("ascii")}
                for s in self.signatures
            ],
        }

    @classmethod
    def from_data(cls, data: object) -> "Envelope":
        try:
            if not isinstance(data, dict):
                raise TypeError("envelope must be an object")
            signatures = tuple(
                Signature(str(s["keyid"]), base64.b64decode(s["sig"], validate=True))
                for s in data["signatures"]
            )
            payload = base64.b64decode(data["payload"], validate=True)
            payload_type = data["payloadType"]
            if not isinstance(payload_type, str):
                raise TypeError("payloadType must be a string")
        except (KeyError, TypeError, ValueError) as exc:
            raise SigningError(f"malformed DSSE envelope: {exc}") from exc
        return cls(payload_type, payload, signatures)

    def verified_by(
        self, resolve: Callable[[str], VerifyKey | None]
    ) -> tuple[list[str], list[str]]:
        """Check every signature. Returns (key ids that verified, key ids that did not).

        Signatures from keys ``resolve`` does not know are in neither list.
        """
        message = pae(self.payload_type, self.payload)
        good: list[str] = []
        bad: list[str] = []
        for signature in self.signatures:
            key = resolve(signature.key_id)
            if key is None:
                continue
            (good if key.verify(signature.sig, message) else bad).append(signature.key_id)
        return good, bad


def sign_envelope(payload_type: str, payload: bytes, *signers: Signer) -> Envelope:
    message = pae(payload_type, payload)
    return Envelope(
        payload_type, payload, tuple(Signature(s.key_id, s.sign(message)) for s in signers)
    )


def restrict_permissions(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.chmod(0o600)
