"""Sigstore bundles, as written by OpenSSF model signing (``model.sig``), verified offline.

A bundle holds a DSSE envelope (an in-toto statement listing every file of the model with its
sha256) and the material to verify its signature. Three ways of signing are supported:

* **key**: a bare public key. The policy pins the key (``type: x509``, a PEM public key).
* **certificate**: a certificate chain from your own PKI. The policy pins the CA certificate
  (``type: x509``); the chain must lead to it and be valid now.
* **sigstore** (keyless): a short-lived Fulcio certificate and a Rekor transparency-log entry.
  The policy pins the Sigstore trusted root (``type: sigstore``, the ``trusted_root.json``
  distributed by Sigstore's TUF repository) and the signer identities it accepts. Verification is
  entirely offline: the certificate must chain to a Fulcio CA in the trusted root; the log entry's
  signed entry timestamp must verify with a Rekor key from the trusted root; the certificate must
  have been valid at the logged time; the log entry must record this signature; and the
  certificate's identity and OIDC issuer must match the policy.

Outcomes: ``verified``; ``invalid`` (the signature, log promise or log entry does not hold:
something was altered); ``untrusted`` (it holds, but not for a key, CA or identity the policy
trusts); ``unverifiable`` (the policy pins nothing that could check it).
"""

import base64
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ObjectIdentifier

from airlock.core.signing import pae

_ISSUER_V2 = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")  # DER UTF8String
_ISSUER_V1 = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")  # raw bytes (deprecated)

PublicKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | rsa.RSAPublicKey


class BundleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Bundle:
    media_type: str
    payload_type: str
    payload: bytes
    signature: bytes
    key_hint: str | None
    certificates: tuple[x509.Certificate, ...]  # leaf first
    tlog: tuple[dict[str, Any], ...]
    statement: dict[str, Any]

    @property
    def method(self) -> str:
        if not self.certificates:
            return "key"
        return "sigstore" if fulcio_issuer(self.certificates[0]) else "certificate"

    def resources(self) -> dict[str, tuple[str, str]]:
        """File name -> (algorithm, hex digest), from the statement."""
        found: dict[str, tuple[str, str]] = {}
        predicate = self.statement.get("predicate")
        for item in predicate.get("resources", []) if isinstance(predicate, dict) else []:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                found[item["name"]] = (
                    str(item.get("algorithm", "sha256")),
                    str(item.get("digest")),
                )
        if not found:  # older statements list files as subjects
            for subject in self.statement.get("subject") or []:
                digest = subject.get("digest") if isinstance(subject, dict) else None
                if isinstance(digest, dict) and "sha256" in digest:
                    found[str(subject.get("name"))] = ("sha256", str(digest["sha256"]))
        return found

    def ignored(self) -> list[str]:
        predicate = self.statement.get("predicate")
        serialization_ = predicate.get("serialization") if isinstance(predicate, dict) else None
        paths = serialization_.get("ignore_paths") if isinstance(serialization_, dict) else None
        return [str(p) for p in paths] if isinstance(paths, list) else []


@dataclass(slots=True)
class Outcome:
    status: str  # verified | invalid | untrusted | unverifiable
    method: str
    signer: str | None = None
    anchor: str | None = None
    reasons: list[str] = field(default_factory=list)


def _b64(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise BundleError(f"{what} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise BundleError(f"{what} is not base64") from exc


def parse_bundle(data: bytes) -> Bundle:
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError(f"not JSON: {exc}") from exc
    if not isinstance(doc, dict) or "dsseEnvelope" not in doc:
        raise BundleError("not a Sigstore bundle with a DSSE envelope")
    envelope = doc["dsseEnvelope"]
    material = doc.get("verificationMaterial") or {}
    if not isinstance(envelope, dict) or not isinstance(material, dict):
        raise BundleError("malformed bundle")
    signatures = envelope.get("signatures") or []
    if len(signatures) != 1 or not isinstance(signatures[0], dict):
        raise BundleError("expected exactly one signature")
    payload = _b64(envelope.get("payload"), "payload")
    certificates: list[x509.Certificate] = []
    raw = []
    if isinstance(material.get("certificate"), dict):
        raw = [material["certificate"].get("rawBytes")]
    elif isinstance(material.get("x509CertificateChain"), dict):
        raw = [c.get("rawBytes") for c in material["x509CertificateChain"].get("certificates", [])]
    for item in raw:
        try:
            certificates.append(x509.load_der_x509_certificate(_b64(item, "certificate")))
        except ValueError as exc:
            raise BundleError(f"unreadable certificate: {exc}") from exc
    try:
        statement = json.loads(payload)
    except ValueError as exc:
        raise BundleError(f"payload is not JSON: {exc}") from exc
    hint = (
        material.get("publicKey", {}).get("hint")
        if isinstance(material.get("publicKey"), dict)
        else None
    )
    tlog = tuple(e for e in material.get("tlogEntries") or [] if isinstance(e, dict))
    return Bundle(
        media_type=str(doc.get("mediaType")),
        payload_type=str(envelope.get("payloadType")),
        payload=payload,
        signature=_b64(signatures[0].get("sig"), "signature"),
        key_hint=str(hint) if hint else None,
        certificates=tuple(certificates),
        tlog=tlog,
        statement=statement if isinstance(statement, dict) else {},
    )


# --- primitives ---------------------------------------------------------------------------------


def verify_signature(key: object, signature: bytes, message: bytes) -> bool:
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            for algorithm in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
                try:
                    key.verify(signature, message, ec.ECDSA(algorithm))
                    return True
                except InvalidSignature:
                    continue
            return False
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
            return True
        if isinstance(key, rsa.RSAPublicKey):
            for pad in (padding.PKCS1v15(), padding.PSS(padding.MGF1(hashes.SHA256()), 32)):
                try:
                    key.verify(signature, message, pad, hashes.SHA256())
                    return True
                except InvalidSignature:
                    continue
            return False
    except InvalidSignature:
        return False
    return False


def fingerprint(key: object) -> str:
    """sha256 of the DER SubjectPublicKeyInfo, as hex."""
    assert hasattr(key, "public_bytes")  # noqa: S101
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _valid_at(cert: x509.Certificate, moment: datetime) -> bool:
    return cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc


def fulcio_issuer(cert: x509.Certificate) -> str | None:
    for oid, der in ((_ISSUER_V2, True), (_ISSUER_V1, False)):
        try:
            value = cert.extensions.get_extension_for_oid(oid).value
        except x509.ExtensionNotFound:
            continue
        raw = value.value if isinstance(value, x509.UnrecognizedExtension) else b""
        if der and len(raw) > 2 and raw[0] == 0x0C:
            length, start = raw[1], 2
            if length & 0x80:
                count = length & 0x7F
                length, start = int.from_bytes(raw[2 : 2 + count], "big"), 2 + count
            return raw[start : start + length].decode("utf-8", "replace")
        return raw.decode("utf-8", "replace")
    return None


def identities(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [
        *san.get_values_for_type(x509.RFC822Name),
        *san.get_values_for_type(x509.UniformResourceIdentifier),
    ]


def load_anchor_key(data: bytes) -> object:
    """A PEM public key, or the public key of a PEM certificate."""
    if b"CERTIFICATE" in data:
        return x509.load_pem_x509_certificate(data).public_key()
    return serialization.load_pem_public_key(data)


# --- the three methods ---------------------------------------------------------------------------


def verify_key(bundle: Bundle, anchors: Sequence[tuple[str, bytes]]) -> Outcome:
    outcome = Outcome("unverifiable", "key")
    message = pae(bundle.payload_type, bundle.payload)
    for name, data in anchors:
        try:
            key = load_anchor_key(data)
        except ValueError:
            continue
        outcome.status = "untrusted"
        if verify_signature(key, bundle.signature, message):
            return Outcome("verified", "key", signer=f"sha256:{fingerprint(key)}", anchor=name)
    outcome.reasons.append(
        "no key pinned in the policy verifies the signature"
        if outcome.status == "untrusted"
        else "the policy pins no public key for models"
    )
    return outcome


def verify_certificate(
    bundle: Bundle, anchors: Sequence[tuple[str, bytes]], now: datetime
) -> Outcome:
    chain = list(bundle.certificates)
    leaf = chain[0]
    message = pae(bundle.payload_type, bundle.payload)
    roots = []
    for name, data in anchors:
        if b"CERTIFICATE" in data:
            try:
                roots.append((name, x509.load_pem_x509_certificate(data)))
            except ValueError:
                continue
    if not roots:
        return Outcome("unverifiable", "certificate", reasons=["the policy pins no CA certificate"])
    for name, root in roots:
        path = chain + ([] if any(c == root for c in chain) else [root])
        if all(_issued_by(path[i], path[i + 1]) for i in range(len(path) - 1)):
            expired = [c.subject.rfc4514_string() for c in path if not _valid_at(c, now)]
            if expired:
                return Outcome(
                    "untrusted",
                    "certificate",
                    anchor=name,
                    reasons=[f"certificate not valid now: {expired[0]}"],
                )
            if not verify_signature(leaf.public_key(), bundle.signature, message):
                return Outcome(
                    "invalid", "certificate", anchor=name, reasons=["the signature does not verify"]
                )
            return Outcome(
                "verified", "certificate", signer=leaf.subject.rfc4514_string() or None, anchor=name
            )
    return Outcome("untrusted", "certificate", reasons=["the chain does not lead to a pinned CA"])


def _set_message(entry: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "body": entry["canonicalizedBody"],
            "integratedTime": int(entry["integratedTime"]),
            "logID": base64.b64decode(entry["logId"]["keyId"]).hex(),
            "logIndex": int(entry["logIndex"]),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _time(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _window(item: dict[str, Any], moment: datetime) -> bool:
    """Whether a trusted-root entry was valid at ``moment`` (open-ended when no end is given)."""
    valid = item.get("validFor") or {}
    start, end = valid.get("start"), valid.get("end")
    return (not start or _time(start) <= moment) and (not end or moment <= _time(end))


def verify_sigstore(
    bundle: Bundle, anchors: Sequence[tuple[str, bytes, Sequence[str], Sequence[str]]]
) -> Outcome:
    """``anchors``: (name, trusted_root.json, accepted identities, accepted issuers)."""
    leaf = bundle.certificates[0]
    message = pae(bundle.payload_type, bundle.payload)
    signer = ", ".join(identities(leaf)) or None
    issuer = fulcio_issuer(leaf)
    if not anchors:
        return Outcome(
            "unverifiable",
            "sigstore",
            signer=signer,
            reasons=["the policy pins no Sigstore trusted root"],
        )
    if not verify_signature(leaf.public_key(), bundle.signature, message):
        return Outcome(
            "invalid", "sigstore", signer=signer, reasons=["the signature does not verify"]
        )
    entries = [e for e in bundle.tlog if isinstance(e.get("inclusionPromise"), dict)]
    if not entries:
        return Outcome(
            "unverifiable", "sigstore", signer=signer,
            reasons=["no transparency-log promise; RFC 3161 timestamps are not verified yet"],
        )  # fmt: skip
    entry = entries[0]
    reasons: list[str] = []
    for name, data, accepted, issuers in anchors:
        try:
            root = json.loads(data)
            moment = datetime.fromtimestamp(int(entry["integratedTime"]), UTC)
        except (ValueError, KeyError, TypeError) as exc:
            reasons.append(f"{name}: unreadable trusted root or log entry: {exc}")
            continue
        log = next(
            (
                t for t in root.get("tlogs", [])
                if t.get("logId", {}).get("keyId") == entry.get("logId", {}).get("keyId")
            ),
            None,
        )  # fmt: skip
        if log is None or not _window(log.get("publicKey", {}), moment):
            reasons.append(f"{name}: the log entry is from a log the trusted root does not list")
            continue
        try:
            log_key = serialization.load_der_public_key(
                _b64(log["publicKey"]["rawBytes"], "log key")
            )
            promise = _b64(entry["inclusionPromise"].get("signedEntryTimestamp"), "log promise")
            set_ok = verify_signature(log_key, promise, _set_message(entry))
            body = json.loads(_b64(entry["canonicalizedBody"], "log entry"))
        except (ValueError, KeyError, TypeError) as exc:
            return Outcome(
                "invalid", "sigstore", signer=signer, anchor=name, reasons=[f"log entry: {exc}"]
            )
        if not set_ok:
            return Outcome(
                "invalid",
                "sigstore",
                signer=signer,
                anchor=name,
                reasons=["the log's signed entry timestamp does not verify"],
            )
        spec = body.get("spec") or {}
        payload_hash = (spec.get("payloadHash") or {}).get("value")
        logged = {s.get("signature") for s in spec.get("signatures") or [] if isinstance(s, dict)}
        if (
            payload_hash != hashlib.sha256(bundle.payload).hexdigest()
            and base64.b64encode(bundle.signature).decode() not in logged
        ):
            return Outcome(
                "invalid",
                "sigstore",
                signer=signer,
                anchor=name,
                reasons=["the log entry records a different signature"],
            )
        chained = False
        for authority in root.get("certificateAuthorities", []):
            if not _window(authority, moment):
                continue
            certs = [
                x509.load_der_x509_certificate(base64.b64decode(c["rawBytes"]))
                for c in authority.get("certChain", {}).get("certificates", [])
            ]
            path = [leaf, *certs]
            if certs and all(_issued_by(path[i], path[i + 1]) for i in range(len(path) - 1)):
                chained = True
                break
        if not chained:
            reasons.append(
                f"{name}: the certificate does not chain to a Fulcio CA in the trusted root"
            )
            continue
        if not _valid_at(leaf, moment):
            return Outcome(
                "invalid",
                "sigstore",
                signer=signer,
                anchor=name,
                reasons=["the certificate was not valid when the signature was logged"],
            )
        ids = identities(leaf)
        if not any(fnmatchcase(i, pattern) for i in ids for pattern in accepted):
            reasons.append(f"{name}: signer {signer} is not an accepted identity")
            continue
        if issuers and not any(fnmatchcase(issuer or "", pattern) for pattern in issuers):
            reasons.append(f"{name}: OIDC issuer {issuer} is not accepted")
            continue
        return Outcome("verified", "sigstore", signer=f"{signer} ({issuer})", anchor=name)
    return Outcome("untrusted", "sigstore", signer=signer, reasons=reasons)
