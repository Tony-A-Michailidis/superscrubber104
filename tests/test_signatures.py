"""OpenSSF model signatures: key, certificate and Sigstore keyless, verified offline.

Everything is generated here: keys, a CA, a Fulcio-like certificate with the OIDC issuer
extension, and a Rekor-like log entry with its signed entry timestamp. The verifier was also
checked against the model-signing project's published test signatures (all three methods).
"""

import base64
import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from airlock.core.model import Result, TrustLevel, UnitKind, Verdict
from airlock.core.signing import pae
from tests.data_fixtures import embedding_model
from tests.helpers import NOW
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import write

MODEL = embedding_model("model")
ISSUER = "https://accounts.example.org"
SIGNER = "release-bot@example.org"


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: tuple[str, ec.EllipticCurvePrivateKey] | None = None,
    *,
    ca: bool = False,
    email: str | None = None,
    oidc: str | None = None,
    start: datetime = NOW - timedelta(days=1),
    days: float = 3650,
) -> x509.Certificate:
    issuer_name, issuer_key = issuer or (subject, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if email:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False
        )
    if oidc:
        value = oidc.encode()
        der = bytes([0x0C, len(value)]) + value
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), der),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _statement(files: dict[str, bytes | str]) -> bytes:
    resources = [
        {"algorithm": "sha256", "name": name.removeprefix("model/"), "digest": hashlib.sha256(
            data.encode() if isinstance(data, str) else data).hexdigest()}
        for name, data in sorted(files.items())
    ]  # fmt: skip
    return json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "model", "digest": {"sha256": "0" * 64}}],
            "predicateType": "https://model_signing/signature/v1.0",
            "predicate": {
                "resources": resources,
                "serialization": {
                    "method": "files",
                    "hash_type": "sha256",
                    "ignore_paths": [".git"],
                },
            },
        }
    ).encode()


def _bundle(payload: bytes, key: ec.EllipticCurvePrivateKey, material: Mapping[str, object]) -> str:
    signature = key.sign(pae("application/vnd.in-toto+json", payload), ec.ECDSA(hashes.SHA256()))
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": material,
            "dsseEnvelope": {
                "payload": base64.b64encode(payload).decode(),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": base64.b64encode(signature).decode(), "keyid": ""}],
            },
        }
    )


def _der(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _policy(anchors: list[tuple[str, str, bytes, str]], tmp: Path) -> str:
    """anchors: (name, type, file content, extra yaml)."""
    tmp.mkdir(parents=True, exist_ok=True)
    lines = ["trust:", "  upstream:"]
    for name, kind, data, extra in anchors:
        path = tmp / f"{name}.anchor"
        path.write_bytes(data)
        lines += [
            f"    - name: {name}",
            f"      type: {kind}",
            f"      file: {path.as_posix()}",
            f'      sha256: "{hashlib.sha256(data).hexdigest()}"',
            '      scope: ["model.*"]',
            *([f"      {extra}"] if extra else []),
        ]
    return "\n".join(lines) + "\n"


def _signature(result, rule: str):  # type: ignore[no-untyped-def]
    return [f for f in findings_of(result).get(rule, []) if f.result is not Result.PASS]


# --- key ----------------------------------------------------------------------------------------


def test_key_signature_verified_and_recorded(tmp_path: Path) -> None:
    key = _key()
    files = dict(MODEL)
    files["model/model.sig"] = _bundle(_statement(MODEL), key, {"publicKey": {"hint": "x"}})
    policy = _policy([("publisher", "x509", _pem(key.public_key()), "")], tmp_path / "keys")
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    assert not _signature(result, "model.signature.untrusted")
    assert not _signature(result, "model.signature.incomplete")
    [package] = [u for u in result.analysis.units if u.kind is UnitKind.MODEL_PACKAGE]
    assert package.attributes["signature"]["status"] == "verified"
    weights = next(a for a in result.analysis.artifacts if a.ref.path == "model/model.safetensors")
    [check] = [v for v in weights.verifications if v.type == "model-signing"]
    assert (check.level, check.anchor) == (TrustLevel.SIGNATURE, "publisher")


def test_untrusted_key_unsigned_file_and_tampering(tmp_path: Path) -> None:
    files = dict(MODEL)
    files["model/model.sig"] = _bundle(_statement(MODEL), _key(), {"publicKey": {"hint": "x"}})
    files["model/extra_instructions.txt"] = "added after signing"
    files["model/vocab.txt"] = "tampered\n"
    policy = _policy([("publisher", "x509", _pem(_key().public_key()), "")], tmp_path / "keys")
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    [untrusted] = _signature(result, "model.signature.untrusted")
    assert untrusted.detail["status"] == "untrusted"
    [mismatch] = _signature(result, "model.signature.digest-mismatch")
    assert mismatch.subject.display == "model/vocab.txt"
    assert result.assessment.summary.verdict is Verdict.REFUSED
    [incomplete] = _signature(result, "model.signature.incomplete")
    assert "vocab.txt" in incomplete.detail["unsigned"]


# --- certificate --------------------------------------------------------------------------------


def test_certificate_chain(tmp_path: Path) -> None:
    root_key, leaf_key = _key(), _key()
    root = _cert("Example Root CA", root_key, ca=True)
    leaf = _cert("model-publisher", leaf_key, ("Example Root CA", root_key))
    material = {"x509CertificateChain": {"certificates": [{"rawBytes": _der(leaf)}]}}
    files = dict(MODEL)
    files["model/model.sig"] = _bundle(_statement(MODEL), leaf_key, material)
    ca_pem = root.public_bytes(serialization.Encoding.PEM)
    policy = _policy([("publisher-ca", "x509", ca_pem, "")], tmp_path / "keys")
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    assert not _signature(result, "model.signature.untrusted")
    assert not _signature(result, "model.signature.invalid")

    # signed by the leaf's certificate but not by its key: the chain is trusted, the signature fails
    files["model/model.sig"] = _bundle(_statement(MODEL), _key(), material)
    result = inspect(write(tmp_path / "e", files), policy_yaml=policy)
    [invalid] = _signature(result, "model.signature.invalid")
    assert invalid.detail["reasons"] == ["the signature does not verify"]
    assert result.assessment.summary.verdict is Verdict.REFUSED


# --- sigstore keyless ---------------------------------------------------------------------------


def _sigstore(tmp_path: Path, *, signer: str = SIGNER, corrupt_promise: bool = False):  # type: ignore[no-untyped-def]
    root_key, intermediate_key, leaf_key, log_key = _key(), _key(), _key(), _key()
    root = _cert("sigstore", root_key, ca=True, start=NOW - timedelta(days=400))
    intermediate = _cert(
        "sigstore-intermediate", intermediate_key, ("sigstore", root_key), ca=True,
        start=NOW - timedelta(days=300),
    )  # fmt: skip
    signed_at = NOW - timedelta(days=2)
    leaf = _cert(
        "sigstore-leaf", leaf_key, ("sigstore-intermediate", intermediate_key), email=signer, oidc=ISSUER,
        start=signed_at - timedelta(minutes=1), days=10 / 1440,
    )  # fmt: skip
    payload = _statement(MODEL)
    envelope = json.loads(_bundle(payload, leaf_key, {}))
    log_id = hashlib.sha256(
        log_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).digest()  # fmt: skip
    body = base64.b64encode(
        json.dumps(
            {
                "apiVersion": "0.0.1",
                "kind": "dsse",
                "spec": {
                    "payloadHash": {
                        "algorithm": "sha256",
                        "value": hashlib.sha256(payload).hexdigest(),
                    },
                    "signatures": [{"signature": envelope["dsseEnvelope"]["signatures"][0]["sig"]}],
                },
            }
        ).encode()
    ).decode()
    entry = {
        "logIndex": "42",
        "logId": {"keyId": base64.b64encode(log_id).decode()},
        "kindVersion": {"kind": "dsse", "version": "0.0.1"},
        "integratedTime": str(int(signed_at.timestamp())),
        "canonicalizedBody": body,
    }
    message = json.dumps(
        {"body": body, "integratedTime": int(entry["integratedTime"]), "logID": log_id.hex(), "logIndex": 42},
        sort_keys=True, separators=(",", ":"),
    ).encode()  # fmt: skip
    promise = log_key.sign(message, ec.ECDSA(hashes.SHA256()))
    if corrupt_promise:
        promise = log_key.sign(message + b" ", ec.ECDSA(hashes.SHA256()))
    entry["inclusionPromise"] = {"signedEntryTimestamp": base64.b64encode(promise).decode()}
    envelope["verificationMaterial"] = {
        "certificate": {"rawBytes": _der(leaf)},
        "tlogEntries": [entry],
    }
    trusted_root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "baseUrl": "https://log.example.org",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": base64.b64encode(
                        log_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    ).decode(),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": "2020-01-01T00:00:00Z"},
                },
                "logId": {"keyId": base64.b64encode(log_id).decode()},
            }
        ],
        "certificateAuthorities": [
            {
                "uri": "https://fulcio.example.org",
                "certChain": {"certificates": [{"rawBytes": _der(intermediate)}, {"rawBytes": _der(root)}]},
                "validFor": {"start": "2020-01-01T00:00:00Z"},
            }
        ],
    }  # fmt: skip
    files = dict(MODEL)
    files["model/model.sig"] = json.dumps(envelope)
    extra = f'identities: ["{SIGNER}"]\n      issuers: ["{ISSUER}"]'
    policy = _policy(
        [("sigstore", "sigstore", json.dumps(trusted_root).encode(), extra)], tmp_path / "root"
    )
    return inspect(write(tmp_path / "d", files), policy_yaml=policy)


def test_sigstore_keyless_verified_offline(tmp_path: Path) -> None:
    result = _sigstore(tmp_path)
    assert not _signature(result, "model.signature.untrusted")
    assert not _signature(result, "model.signature.invalid")
    [package] = [u for u in result.analysis.units if u.kind is UnitKind.MODEL_PACKAGE]
    assert package.attributes["signature"]["signer"] == f"{SIGNER} ({ISSUER})"


def test_sigstore_wrong_identity_and_forged_log_promise(tmp_path: Path) -> None:
    result = _sigstore(tmp_path / "a", signer="someone@elsewhere.example")
    [untrusted] = _signature(result, "model.signature.untrusted")
    assert "not an accepted identity" in untrusted.detail["reasons"][0]
    result = _sigstore(tmp_path / "b", corrupt_promise=True)
    [invalid] = _signature(result, "model.signature.invalid")
    assert "signed entry timestamp" in invalid.detail["reasons"][0]


def test_unpinned_signature_is_reported_not_trusted(tmp_path: Path) -> None:
    files = dict(MODEL)
    files["model/model.sig"] = _bundle(_statement(MODEL), _key(), {"publicKey": {"hint": "x"}})
    [finding] = _signature(inspect(write(tmp_path / "d", files)), "model.signature.untrusted")
    assert finding.detail["status"] == "unverifiable"
