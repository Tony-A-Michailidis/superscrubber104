"""Synthetic Zarf packages, built to the layout of a real one (doc 35 §35.2).

A package here is a dict of member name to bytes: ``zarf.yaml``, ``checksums.txt`` (filled in by
``build``), optionally ``zarf.bundle.sig``, ``components/<name>.tar``, an OCI layout under
``images/`` and ``sboms.tar``. Tests change members after building to tamper with a package, then
turn it into a tar (or, on Python 3.14, a ``.tar.zst``) with ``package_bytes``.

Signatures use throwaway keys: a bare key, or a Fulcio-like certificate with a Rekor-like
``hashedrekord`` log entry and a trusted root that pins both.
"""

import base64
import copy
import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

from tests.helpers import NOW
from tests.model_fixtures import safetensors_bytes
from tests.test_signatures import _cert, _der, _key, _pem

SIGNER = "https://ci.example.org/release.yml@refs/tags/v1.0.0"
ISSUER = "https://token.example.org"
TOOL = b"#!/bin/sh\necho 'a tool the package places on the host'\n"
MANIFEST = b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\ndata:\n  mode: offline\n"
NAME = "zarf-package-demo-app-amd64-1.0.0.tar"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar(members: Mapping[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755 if name.endswith("tool") else 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def image_layout(images: Mapping[str, Mapping[str, bytes]]) -> dict[str, bytes]:
    """``images/`` members for one single-layer image per reference."""
    blobs: dict[str, bytes] = {}
    manifests = []
    for reference, files in images.items():
        layer_tar = tar(files)
        layer = gzip.compress(layer_tar, mtime=0)
        config = json.dumps(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {"User": "1000", "Cmd": ["/app/run"]},
                "rootfs": {"type": "layers", "diff_ids": [f"sha256:{sha(layer_tar)}"]},
            }
        ).encode()
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": f"sha256:{sha(config)}",
                    "size": len(config),
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": f"sha256:{sha(layer)}",
                        "size": len(layer),
                    }
                ],
            }
        ).encode()
        for blob in (layer, config, manifest):
            blobs[f"images/blobs/sha256/{sha(blob)}"] = blob
        manifests.append(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{sha(manifest)}",
                "size": len(manifest),
                "annotations": {"org.opencontainers.image.ref.name": reference},
            }
        )
    index = json.dumps({"schemaVersion": 2, "manifests": manifests}).encode()
    return {
        "images/oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "images/index.json": index,
        **blobs,
    }


IMAGES: dict[str, dict[str, bytes]] = {
    "docker.io/library/demo-app:1.0": {"app/run": b"#!/bin/sh\nexec /app/server\n"},
    "ghcr.io/example/model-server:2.1": {
        "models/tiny/model.safetensors": safetensors_bytes({"embeddings.weight": ("F32", (4, 8))}),
        "models/tiny/config.json": b'{"model_type": "bert", "hidden_size": 8}',
    },
}


def definition(**build: object) -> dict[str, Any]:
    """A v1alpha1 package definition (no ``apiVersion``, as Zarf 1.0's init package)."""
    return {
        "kind": "ZarfPackageConfig",
        "metadata": {"name": "demo-app", "version": "1.0.0", "architecture": "amd64"},
        "build": {
            "architecture": "amd64",
            "version": "v1.0.1",
            "signed": False,
            "provenanceFiles": ["checksums.txt", "zarf.bundle.sig"],
            **build,
        },
        "components": [
            {
                "name": "app",
                "required": True,
                "images": ["library/demo-app:1.0", "ghcr.io/example/model-server:2.1"],
                "manifests": [{"name": "demo", "namespace": "demo", "files": ["demo.yaml"]}],
                "files": [
                    {
                        "source": "https://example.org/releases/tool",
                        "shasum": sha(TOOL),
                        "target": "###ZARF_TEMP###/tool",
                        "executable": True,
                    }
                ],
            }
        ],
    }


def components(name: str = "app", files: Mapping[str, bytes] | None = None) -> dict[str, bytes]:
    inner = {f"{name}/files/0/tool": TOOL, f"{name}/manifests/demo-0.yaml": MANIFEST}
    return {f"components/{name}.tar": tar({**inner, **(files or {})})}


class KeySigner:
    def __init__(self) -> None:
        self.key = _key()
        self.public_pem = _pem(self.key.public_key())

    def __call__(self, document: bytes) -> bytes:
        signature = self.key.sign(document, ec.ECDSA(hashes.SHA256()))
        return _message_bundle(document, signature, {"publicKey": {"hint": "demo"}})


class KeylessSigner:
    """A Fulcio-like certificate for ``identity`` and a Rekor-like log, with their trusted root."""

    def __init__(self, identity: str = SIGNER) -> None:
        root_key, intermediate_key, self.leaf_key, self.log_key = _key(), _key(), _key(), _key()
        root = _cert("fulcio-root", root_key, ca=True)
        intermediate = _cert("fulcio-intermediate", intermediate_key, ("fulcio-root", root_key), ca=True)  # fmt: skip
        self.signed_at = NOW - timedelta(days=2)
        start = self.signed_at - timedelta(minutes=1)
        oidc = ISSUER.encode()
        # A CI workflow's identity: a URI in the SAN, and the OIDC issuer extension.
        self.leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(intermediate.subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + timedelta(minutes=10))
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]),
                critical=True,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), bytes([0x0C, len(oidc)]) + oidc
                ),
                critical=False,
            )
            .sign(intermediate_key, hashes.SHA256())
        )
        log_der = self.log_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.log_id = hashlib.sha256(log_der).digest()
        self.trusted_root = json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "tlogs": [
                    {
                        "baseUrl": "https://log.example.org",
                        "hashAlgorithm": "SHA2_256",
                        "publicKey": {
                            "rawBytes": base64.b64encode(log_der).decode(),
                            "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                            "validFor": {"start": "2020-01-01T00:00:00Z"},
                        },
                        "logId": {"keyId": base64.b64encode(self.log_id).decode()},
                    }
                ],
                "certificateAuthorities": [
                    {
                        "uri": "https://fulcio.example.org",
                        "certChain": {
                            "certificates": [
                                {"rawBytes": _der(intermediate)},
                                {"rawBytes": _der(root)},
                            ]
                        },
                        "validFor": {"start": "2020-01-01T00:00:00Z"},
                    }
                ],
            }
        ).encode()

    def __call__(self, document: bytes) -> bytes:
        signature = self.leaf_key.sign(document, ec.ECDSA(hashes.SHA256()))
        encoded = base64.b64encode(signature).decode()
        body = base64.b64encode(
            json.dumps(
                {
                    "apiVersion": "0.0.1",
                    "kind": "hashedrekord",
                    "spec": {
                        "data": {"hash": {"algorithm": "sha256", "value": sha(document)}},
                        "signature": {"content": encoded, "publicKey": {"content": ""}},
                    },
                }
            ).encode()
        ).decode()
        entry: dict[str, Any] = {
            "logIndex": "7",
            "logId": {"keyId": base64.b64encode(self.log_id).decode()},
            "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
            "integratedTime": str(int(self.signed_at.timestamp())),
            "canonicalizedBody": body,
        }
        message = json.dumps(
            {
                "body": body,
                "integratedTime": int(entry["integratedTime"]),
                "logID": self.log_id.hex(),
                "logIndex": 7,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        promise = self.log_key.sign(message, ec.ECDSA(hashes.SHA256()))
        entry["inclusionPromise"] = {"signedEntryTimestamp": base64.b64encode(promise).decode()}
        material = {"certificate": {"rawBytes": _der(self.leaf_cert)}, "tlogEntries": [entry]}
        return _message_bundle(document, signature, material)


def _message_bundle(document: bytes, signature: bytes, material: Mapping[str, object]) -> bytes:
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": material,
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(hashlib.sha256(document).digest()).decode(),
                },
                "signature": base64.b64encode(signature).decode(),
            },
        }
    ).encode()


def build(
    package: Mapping[str, Any] | None = None,
    *,
    images: Mapping[str, Mapping[str, bytes]] | None = None,
    parts: Mapping[str, bytes] | None = None,
    signer: KeySigner | KeylessSigner | None = None,
    aggregate_key: str = "metadata",
) -> dict[str, bytes]:
    """Every member of a consistent package: checksums listed, aggregate set, signed if asked."""
    document = copy.deepcopy(dict(package or definition()))
    members = {
        **(components() if parts is None else dict(parts)),
        **image_layout(IMAGES if images is None else images),
        "sboms.tar": tar({"demo-app.json": b'{"artifacts": []}'}),
    }
    listing = "".join(f"{sha(data)} {name}\n" for name, data in sorted(members.items()))
    checksums = listing.encode()
    section = document.setdefault(aggregate_key, {})
    section["aggregateChecksum"] = sha(checksums)
    if signer is not None:
        document["build"]["signed"] = True
    definition_bytes = yaml.safe_dump(document, sort_keys=False).encode()
    out = {"zarf.yaml": definition_bytes, "checksums.txt": checksums, **members}
    if signer is not None:
        out["zarf.bundle.sig"] = signer(definition_bytes)
    return out


def relist(members: dict[str, bytes]) -> None:
    """Recompute checksums.txt and the aggregate after changing members (an unsigned repack)."""
    payload = {
        k: v
        for k, v in members.items()
        if k not in ("zarf.yaml", "checksums.txt", "zarf.bundle.sig")
    }
    checksums = "".join(f"{sha(d)} {n}\n" for n, d in sorted(payload.items())).encode()
    document = yaml.safe_load(members["zarf.yaml"])
    section = "build" if document.get("apiVersion") == "zarf.dev/v1beta1" else "metadata"
    document[section]["aggregateChecksum"] = sha(checksums)
    members["checksums.txt"] = checksums
    members["zarf.yaml"] = yaml.safe_dump(document, sort_keys=False).encode()


def package_bytes(members: Mapping[str, bytes], *, zstd: bool = False) -> bytes:
    data = tar(members)
    if zstd:
        from superscrubber104.archive import zstd_module

        return bytes(zstd_module().compress(data))
    return data
