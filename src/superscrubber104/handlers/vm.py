"""Virtual machine images and appliances: disk images, OVA/OVF, and OpenStack Glance metadata.

* **Disk images** (qcow2, VMDK, VHD, VHDX, raw, ISO): the format is taken from the bytes, never
  the name; a name or a declaration that says otherwise is ``vm.format.mismatch`` (format
  confusion: a "raw" image that is really qcow2 makes the hypervisor follow its backing file).
  An image that depends on files outside itself (backing file, parent disk, external data file,
  missing extents) is ``vm.image.incomplete``: it will not boot as delivered and its references
  can name paths on the source host. Encryption, unclean state and internal snapshots (which keep
  earlier states of the disk, including data since deleted) are recorded.
* Guest filesystems are never mounted. Their contents are recorded as not assessed
  (``vm.image.contents``) unless a deep-inspection plugin examines them.
* **OVA/OVF**: every file the descriptor references must be present with its declared size; the
  ``.mf`` manifest's hashes are checked (``upstream.checksum-mismatch``, final), and a signed
  manifest (``.cert``) is verified against certificates pinned for ``vm.ova``.
* **Glance metadata** (``openstack image show -f json`` saved beside the image): ``os_hash_value``
  and the legacy md5 ``checksum`` are checked against the image (``vm.metadata.mismatch``,
  final), ``disk_format`` against the bytes, and ``img_signature`` against certificates pinned for
  ``vm.glance``.
"""

import base64
import hashlib
import re
import tarfile
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa, utils

from superscrubber104 import __version__
from superscrubber104.core.canonical import jsonable
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import (
    ArtifactRef,
    Result,
    Subject,
    ToolRef,
    TrustLevel,
    UnitClaim,
    UnitKind,
    Verification,
)
from superscrubber104.core.paths import check_member_name
from superscrubber104.formats.disk import DiskError, DiskInfo, read_disk, sniff
from superscrubber104.handlers.common import TooLarge, mapping, name_of, read_bytes, read_json
from superscrubber104.trust import x509_keys

TOOL = ToolRef("superscrubber104.vm", __version__)
KIND = UnitKind.VM_IMAGE
_BY_EXTENSION = {".qcow2": "qcow2", ".qcow": "qcow2", ".vmdk": "vmdk", ".vhd": "vhd", ".vpc": "vhd",
                 ".vhdx": "vhdx", ".iso": "iso", ".raw": "raw"}  # fmt: skip
_RAW_NAMES = (".img", ".raw", ".dd", ".disk")
_GLANCE_FORMATS = {
    "qcow2": "qcow2",
    "vmdk": "vmdk",
    "vhd": "vhd",
    "vhdx": "vhdx",
    "raw": "raw",
    "iso": "iso",
}
_MF_LINE = re.compile(
    r"^(?P<algo>SHA1|SHA256|SHA512)\s*\((?P<name>[^)]+)\)\s*=\s*(?P<hash>[0-9a-fA-F]+)\s*$"
)
_GLANCE_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "SHA-224": hashes.SHA224,
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}
_OVF_LIMIT = 16 << 20


def _extension(name: str) -> str:
    lower = name.lower()
    return lower[lower.rfind(".") :] if "." in lower else ""


def _vhd_footer(view: ArtifactView) -> bool:
    if view.size < 512:
        return False
    with view.open() as stream:
        stream.seek(view.size - 512)
        return stream.read(8) == b"conectix"


def image_format(view: ArtifactView) -> str | None:
    """The disk format the bytes say, or None if this is not a disk image."""
    head = view.head(1 << 16)
    found = sniff(head)
    name = name_of(view.ref).lower()
    if found in ("qcow2", "vmdk", "vhdx", "vhd", "luks", "iso"):
        return found
    if _extension(name) in (".vhd", ".vpc") and _vhd_footer(view):
        return "vhd"
    if name.endswith(_RAW_NAMES):
        return "raw"  # whether or not it has a partition table: a raw disk is just bytes
    return None


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref)
    lower = name.lower()
    if lower.endswith(".ova") and view.head(512)[257:262] == b"ustar":
        return "vm.ova"
    if lower.endswith(".ovf") and b"Envelope" in view.head(4096):
        return "vm.ovf"
    if (
        lower.endswith(".mf")
        and lower != "manifest.mf"
        and _MF_LINE.match(view.head(256).decode("ascii", "replace").split("\n", 1)[0])
    ):
        return "vm.manifest"
    if lower.endswith(".json") and view.size < 1 << 20:
        head = view.head(1 << 16)
        if b'"disk_format"' in head and (b'"os_hash_value"' in head or b'"checksum"' in head):
            return "vm.glance-metadata"
        return None
    fmt = image_format(view)
    return f"vm.image.{'raw' if fmt == 'luks' else fmt}" if fmt else None


def _claim(
    root: ArtifactRef, role: str, artifact: ArtifactRef, sha256: str | None, **facts: object
) -> UnitClaim:
    return UnitClaim(KIND, root, role, artifact, sha256, {k: jsonable(v) for k, v in facts.items()})


class VmHandler:
    name = "vm"
    version = "1"
    kinds = frozenset(
        {
            "vm.image.qcow2",
            "vm.image.vmdk",
            "vm.image.vhd",
            "vm.image.vhdx",
            "vm.image.raw",
            "vm.image.iso",
            "vm.ova",
            "vm.ovf",
            "vm.manifest",
            "vm.glance-metadata",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 90) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact) or "vm.image.raw"
        if kind == "vm.ova":
            return self._ova(artifact, ctx)
        if kind == "vm.ovf":
            return self._ovf(artifact, ctx)
        if kind == "vm.manifest":
            return self._manifest(artifact, ctx)
        if kind == "vm.glance-metadata":
            return self._glance(artifact, ctx)
        return self._image(artifact, ctx, kind)

    # --- disk images ----------------------------------------------------------------------------

    def _image(self, view: ArtifactView, ctx: Context, kind: str) -> Inspection:
        detected = image_format(view) or "raw"
        subject = Subject.of_artifact(view.ref)
        try:
            with view.open() as stream:
                info = read_disk(stream, detected)
        except (DiskError, OSError, ValueError, UnicodeDecodeError) as exc:
            ctx.recorder.not_assessed(
                ("vm.image.incomplete", "vm.image.contents"),
                subject,
                tool=TOOL,
                reason=f"{detected} header could not be read: {exc}",
            )
            return Inspection(
                kind=kind, metadata={"vmImage": {"format": detected, "error": str(exc)[:300]}}
            )
        expected = _BY_EXTENSION.get(_extension(name_of(view.ref)))
        if expected and expected != info.format and not (expected == "raw" and detected == "luks"):
            ctx.recorder.fail(
                "vm.format.mismatch",
                subject,
                tool=TOOL,
                detail={"declared": expected, "declaredBy": "file name", "actual": info.format},
            )
        missing_extents = self._extents(view, info)
        record_disk(view.ref, info, ctx, missing_extents)
        summary = _summary(info)
        claim = _claim(view.ref, "disk", view.ref, view.sha256, **summary)
        return Inspection(kind=kind, metadata={"vmImage": summary}, claims=(claim,))

    def _extents(self, view: ArtifactView, info: DiskInfo) -> list[str]:
        """Extent files a VMDK descriptor names that are not beside it."""
        missing = []
        extents = info.details.get("extents")
        for extent in extents if isinstance(extents, list) else []:
            file = extent.get("file") if isinstance(extent, dict) else None
            if not file or file == name_of(view.ref):
                continue
            if view.ref.nested or view.resolve(file) is None:
                missing.append(file)
        return missing

    # --- OVA, OVF and manifests -----------------------------------------------------------------

    def _ova(self, view: ArtifactView, ctx: Context) -> Inspection:
        digests: dict[str, dict[str, str]] = {}
        sizes: dict[str, int] = {}
        refs: dict[str, ArtifactRef] = {}
        kept: dict[str, bytes] = {}  # the descriptor, manifest and certificate
        wanted = {"sha1", "sha256", "sha512"}
        try:
            with view.open() as stream, tarfile.open(fileobj=stream, mode="r|") as archive:
                for member in archive:
                    handle = archive.extractfile(member) if member.isfile() else None
                    if handle is None:
                        continue
                    # Named exactly as the analyzer names archive members, so that what is
                    # verified here lands on the artifact it records.
                    name, issue = check_member_name(member.name)
                    if not name:
                        continue
                    lower = name.lower()
                    keep = lower.endswith((".ovf", ".mf", ".cert")) and member.size <= _OVF_LIMIT
                    hashers = {a: hashlib.new(a, usedforsecurity=False) for a in sorted(wanted)}
                    content = bytearray()
                    while block := handle.read(1 << 20):
                        for hasher in hashers.values():
                            hasher.update(block)
                        if keep:
                            content += block
                    digests[name] = {a: h.hexdigest() for a, h in hashers.items()}
                    sizes[name] = member.size
                    refs[name] = view.ref.child(name, unsafe=issue is not None)
                    if keep:
                        kept.setdefault(lower.rsplit(".", 1)[-1], bytes(content))
                    if lower.endswith(".mf") and keep:
                        # The manifest comes before the disks: from here on, only the
                        # algorithms it uses need computing.
                        used = {a.lower() for a, _, _ in _manifest_lines(_ascii(bytes(content)))}
                        wanted = used or wanted
        except (tarfile.TarError, OSError, EOFError) as exc:
            ctx.recorder.not_assessed(
                ("vm.image.incomplete", "upstream.checksum-mismatch"),
                Subject.of_artifact(view.ref),
                tool=TOOL,
                reason=f"unreadable OVA: {exc}",
            )
            return Inspection(kind="vm.ova", metadata={"vmAppliance": {"error": str(exc)[:300]}})
        manifest = _ascii(kept["mf"]) if "mf" in kept else None
        signed = None
        if manifest is not None and "cert" in kept:
            signed = _ova_certificate(view, kept["mf"], kept["cert"], ctx)
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        manifest_ok = None
        listed: set[str] = set()
        if manifest is not None:
            manifest_ok = True
            for algo, name, expected in _manifest_lines(manifest):
                name = name.removeprefix("./")
                listed.add(name)
                actual = digests.get(name, {}).get(algo.lower())
                if actual is None:
                    continue  # not in the archive: the descriptor's references decide below
                if actual != expected.lower():
                    manifest_ok = False
                    ctx.recorder.fail(
                        "upstream.checksum-mismatch",
                        Subject.of_artifact(refs[name]),
                        tool=TOOL,
                        detail={
                            "list": "OVA manifest",
                            "algorithm": algo.lower(),
                            "listed": expected.lower(),
                            "actual": actual,
                        },
                    )
                else:
                    verifications[refs[name]] = (
                        signed
                        or Verification(
                            "ovf-manifest",
                            TrustLevel.CHECKSUM,
                            Result.PASS,
                            anchor=name_of(view.ref),
                        ),
                    )
            if manifest_ok and listed:
                ctx.recorder.passed("upstream.checksum-mismatch")
        summary: dict[str, object] = {
            "files": len(digests),
            "manifest": manifest is not None,
            "manifestVerified": manifest_ok,
            "certificate": "cert" in kept,
            "signatureVerified": signed is not None,
            # Files the manifest does not vouch for (the manifest and certificate never are).
            "unlisted": sorted(
                n for n in digests if n not in listed and not n.lower().endswith((".mf", ".cert"))
            )[:50]
            if manifest is not None
            else [],
        }
        if "ovf" in kept:
            try:
                descriptor = _parse_ovf(kept["ovf"])
            except ET.ParseError as exc:
                ctx.recorder.not_assessed(
                    ("vm.image.incomplete",),
                    Subject.of_artifact(view.ref),
                    tool=TOOL,
                    reason=f"the OVF descriptor does not parse: {exc}",
                )
            else:
                missing = [f for f in descriptor.files if f["href"] not in sizes]
                wrong_size = [
                    f
                    for f in descriptor.files
                    if f["href"] in sizes and f.get("size") not in (None, sizes[f["href"]])
                ]
                _appliance_findings(view.ref, ctx, missing, wrong_size)
                summary |= {
                    "os": descriptor.os,
                    "disks": descriptor.disks,
                    "virtualSystem": descriptor.system,
                }
        claim = _claim(view.ref, "appliance", view.ref, view.sha256, **summary)
        return Inspection(
            kind="vm.ova",
            metadata={"vmAppliance": summary},
            claims=(claim,),
            verifications=verifications,
        )

    def _ovf(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            descriptor = _parse_ovf(read_bytes(view, _OVF_LIMIT))
        except (TooLarge, ET.ParseError) as exc:
            return Inspection(kind="vm.ovf", metadata={"vmAppliance": {"error": str(exc)[:300]}})
        missing, wrong_size = [], []
        for file in descriptor.files:
            target = None if view.ref.nested else view.resolve(file["href"])
            if target is None:
                if not view.ref.nested:
                    missing.append(file)
            elif file.get("size") not in (None, target.size):
                wrong_size.append(file)
        if not view.ref.nested:  # inside an OVA the OVA's own pass has checked this
            _appliance_findings(view.ref, ctx, missing, wrong_size)
        summary = {
            "os": descriptor.os,
            "disks": descriptor.disks,
            "virtualSystem": descriptor.system,
            "files": len(descriptor.files),
        }
        inside_ova = view.ref.nested and view.ref.path.lower().endswith(".ova")
        claims = (
            () if inside_ova else (_claim(view.ref, "appliance", view.ref, view.sha256, **summary),)
        )
        return Inspection(kind="vm.ovf", metadata={"vmAppliance": summary}, claims=claims)

    def _manifest(self, view: ArtifactView, ctx: Context) -> Inspection:
        if view.ref.nested:
            return Inspection(kind="vm.manifest", metadata={"vmManifest": {"checkedBy": "the OVA"}})
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        checked = 0
        for algo, name, expected in _manifest_lines(
            read_bytes(view, 1 << 20).decode("ascii", "replace")
        ):
            target = view.resolve(name)
            if target is None:
                continue
            checked += 1
            actual = _hexdigest(target, algo.lower())
            if actual != expected.lower():
                ctx.recorder.fail(
                    "upstream.checksum-mismatch",
                    Subject.of_artifact(target.ref),
                    tool=TOOL,
                    detail={
                        "list": name_of(view.ref),
                        "algorithm": algo.lower(),
                        "listed": expected.lower(),
                        "actual": actual,
                    },
                )
            else:
                verifications[target.ref] = (
                    Verification(
                        "ovf-manifest", TrustLevel.CHECKSUM, Result.PASS, anchor=name_of(view.ref)
                    ),
                )
        return Inspection(
            kind="vm.manifest",
            metadata={"vmManifest": {"checked": checked}},
            verifications=verifications,
        )

    # --- Glance ---------------------------------------------------------------------------------

    def _glance(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            meta = mapping(read_json(view))
        except (TooLarge, ValueError) as exc:
            return Inspection(
                kind="vm.glance-metadata", metadata={"glance": {"error": str(exc)[:300]}}
            )
        properties = {
            **mapping(meta.get("properties")),
            **{k: v for k, v in meta.items() if k != "properties"},
        }
        target = self._glance_target(view, meta)
        subject = Subject.of_artifact(view.ref)
        if target is None:
            ctx.recorder.not_assessed(
                ("vm.metadata.mismatch",),
                subject,
                tool=TOOL,
                reason="the image this metadata describes is not beside it",
            )
            return Inspection(
                kind="vm.glance-metadata", metadata={"glance": _glance_summary(properties)}
            )
        algo = str(properties.get("os_hash_algo") or "").lower()
        recorded = ((algo, properties.get("os_hash_value")), ("md5", properties.get("checksum")))
        wanted = {
            name: str(value).lower()
            for name, value in recorded
            if name in ("sha256", "sha384", "sha512", "md5") and value
        }
        actual = _hexdigests(target, wanted)
        problems: list[dict[str, object]] = [
            {
                "field": "os_hash_value" if name != "md5" else "checksum",
                "declared": value,
                "actual": actual.get(name),
            }
            for name, value in wanted.items()
            if actual.get(name) != value
        ]
        size = properties.get("size")
        if isinstance(size, int) and size != target.size:
            problems.append({"field": "size", "declared": size, "actual": target.size})
        verifications: list[Verification] = []
        if problems:
            ctx.recorder.fail(
                "vm.metadata.mismatch",
                Subject.of_artifact(target.ref),
                tool=TOOL,
                detail={"metadata": name_of(view.ref), "problems": problems},
            )
        elif wanted:
            ctx.recorder.passed("vm.metadata.mismatch")
            verifications.append(
                Verification("glance", TrustLevel.CHECKSUM, Result.PASS, anchor=name_of(view.ref))
            )
        declared = _GLANCE_FORMATS.get(str(properties.get("disk_format", "")).lower())
        detected = image_format(target)
        detected = "raw" if detected == "luks" else detected
        if declared and detected and declared != detected:
            ctx.recorder.fail(
                "vm.format.mismatch",
                Subject.of_artifact(target.ref),
                tool=TOOL,
                detail={"declared": declared, "declaredBy": name_of(view.ref), "actual": detected},
            )
        if properties.get("img_signature"):
            verification = self._glance_signature(view, target, properties, ctx)
            if verification is not None:
                verifications.append(verification)
        summary = _glance_summary(properties)
        claim = _claim(target.ref, "metadata", view.ref, view.sha256, **summary)
        return Inspection(
            kind="vm.glance-metadata",
            metadata={"glance": summary},
            claims=(claim,),
            verifications={target.ref: tuple(verifications)} if verifications else {},
        )

    def _glance_target(self, view: ArtifactView, meta: dict[str, object]) -> ArtifactView | None:
        name = name_of(view.ref)
        stem = name[: -len(".json")]
        candidates = [stem, *(f"{stem.rsplit('.', 1)[0]}{ext}" for ext in (*_BY_EXTENSION, ".img"))]
        if isinstance(meta.get("name"), str):
            candidates.append(str(meta["name"]))
        for candidate in candidates:
            if candidate and candidate != name and (target := view.resolve(candidate)) is not None:
                return target
        return None

    def _glance_signature(
        self, view: ArtifactView, target: ArtifactView, properties: dict[str, object], ctx: Context
    ) -> Verification | None:
        subject = Subject.of_artifact(view.ref)
        method = _GLANCE_HASHES.get(str(properties.get("img_signature_hash_method", "")).upper())
        key_type = str(properties.get("img_signature_key_type", ""))
        try:
            signature = base64.b64decode(str(properties["img_signature"]), validate=True)
        except ValueError:
            signature = b""
        if method is None or not signature:
            ctx.recorder.fail(
                "upstream.signature.invalid",
                subject,
                tool=TOOL,
                detail={"reason": "unreadable img_signature or hash method"},
            )
            return None
        keys = x509_keys(ctx, "vm.glance")
        if not keys:
            ctx.recorder.fail(
                "upstream.signature.untrusted",
                subject,
                tool=TOOL,
                detail={
                    "reason": "no certificate is pinned for vm.glance",
                    "certificate": properties.get("img_signature_certificate_uuid"),
                },
            )
            return None
        algorithm = method()
        digest = hashlib.new(algorithm.name)
        with target.open() as stream:
            while block := stream.read(1 << 20):
                digest.update(block)
        value = digest.digest()
        for anchor, key in keys:
            if _glance_verify(key, key_type, signature, value, algorithm):
                ctx.recorder.passed("upstream.signature.invalid")
                return Verification(
                    "glance-signature",
                    TrustLevel.SIGNATURE,
                    Result.PASS,
                    anchor=anchor,
                    detail={"keyType": key_type},
                )
        ctx.recorder.fail(
            "upstream.signature.invalid",
            subject,
            tool=TOOL,
            detail={
                "reason": "img_signature does not verify with any certificate pinned for vm.glance",
                "keyType": key_type,
            },
        )
        return None


def record_disk(
    ref: ArtifactRef, info: DiskInfo, ctx: Context, missing_extents: Iterable[str] = ()
) -> None:
    """The findings every disk image gets, wherever it was found."""
    subject = Subject.of_artifact(ref)
    depends = [*info.depends_on, *({"kind": "extent", "name": e} for e in missing_extents)]
    if depends:
        ctx.recorder.fail(
            "vm.image.incomplete",
            subject,
            tool=TOOL,
            detail={"format": info.format, "dependsOn": depends},
        )
    else:
        ctx.recorder.passed("vm.image.incomplete")
    if info.unclean:
        ctx.recorder.fail(
            "vm.image.unclean",
            subject,
            tool=TOOL,
            detail={"format": info.format, "state": info.unclean},
        )
    if info.snapshots:
        ctx.recorder.fail(
            "vm.image.snapshots", subject, tool=TOOL, detail={"snapshots": info.snapshots}
        )
    if info.encrypted:
        ctx.recorder.fail(
            "vm.image.encrypted", subject, tool=TOOL, detail={"encryption": info.encrypted}
        )
    reason = (
        f"encrypted ({info.encrypted}): the guest contents cannot be read"
        if info.encrypted
        else "guest filesystems are never mounted; no deep-inspection plugin examined them"
    )
    ctx.recorder.not_assessed(("vm.image.contents",), subject, tool=TOOL, reason=reason)


def _summary(info: DiskInfo) -> dict[str, object]:
    return {
        "format": info.format,
        "version": info.version,
        "virtualSize": info.virtual_size,
        "dependsOn": info.depends_on,
        "encrypted": info.encrypted,
        "unclean": info.unclean,
        "snapshots": info.snapshots,
        **{k: v for k, v in info.details.items() if k != "extents"},
    }


def _ascii(data: bytes) -> str:
    return data.decode("ascii", "replace")


def _ova_certificate(
    view: ArtifactView, manifest: bytes, certificate: bytes, ctx: Context
) -> Verification | None:
    """Verify a signed OVA: the ``.cert`` file holds ``SHA256(x.mf)= <signature in hex>`` and the
    signer's certificate; the signature is RSA (PKCS#1 v1.5) over the manifest.

    The embedded certificate proves nothing by itself. The signature counts only when it verifies
    with a key the policy pins for ``vm.ova``.
    """
    subject = Subject.of_artifact(view.ref, locator="certificate")
    text = _ascii(certificate)
    lines = _manifest_lines(text.split("-----BEGIN", 1)[0])
    if not lines:
        ctx.recorder.fail(
            "upstream.signature.untrusted",
            subject,
            tool=TOOL,
            detail={"reason": "the OVA certificate file holds no signature line"},
        )
        return None
    algorithm, _, value = lines[0]
    digests: dict[str, Callable[[], hashes.HashAlgorithm]] = {
        "SHA1": hashes.SHA1,
        "SHA256": hashes.SHA256,
        "SHA512": hashes.SHA512,
    }
    digest = digests[algorithm]
    signature = bytes.fromhex(value) if len(value) % 2 == 0 else b""
    embedded = None
    try:
        block = "-----BEGIN" + text.split("-----BEGIN", 1)[1]
        embedded = _spki(x509.load_pem_x509_certificate(block.encode()).public_key())
    except (IndexError, ValueError):
        embedded = None
    pinned = x509_keys(ctx, "vm.ova")
    for anchor, key in pinned:
        if not isinstance(key, rsa.RSAPublicKey):
            continue
        try:
            key.verify(signature, manifest, padding.PKCS1v15(), digest())
        except (InvalidSignature, ValueError):
            if embedded is not None and _spki(key) == embedded:
                # The pinned signer's own certificate is in the file, and its signature fails.
                ctx.recorder.fail(
                    "upstream.signature.invalid",
                    subject,
                    tool=TOOL,
                    detail={
                        "reason": "the manifest does not match its signature",
                        "anchor": anchor,
                    },
                )
                return None
            continue
        ctx.recorder.passed("upstream.signature.invalid")
        ctx.recorder.passed("upstream.signature.untrusted")
        return Verification("ovf-certificate", TrustLevel.SIGNATURE, Result.PASS, anchor=anchor)
    ctx.recorder.fail(
        "upstream.signature.untrusted",
        subject,
        tool=TOOL,
        detail={
            "reason": "no certificate pinned for vm.ova verifies the manifest's signature"
            if pinned
            else "no certificate is pinned for vm.ova",
        },
    )
    return None


def _spki(key: object) -> bytes:
    return key.public_bytes(  # type: ignore[attr-defined,no-any-return]
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _manifest_lines(text: str) -> list[tuple[str, str, str]]:
    return [
        (m["algo"], m["name"].strip(), m["hash"])
        for line in text.splitlines()
        if (m := _MF_LINE.match(line.strip()))
    ]


def _hexdigest(view: ArtifactView, algorithm: str) -> str:
    return _hexdigests(view, {algorithm: ""})[algorithm]


def _hexdigests(view: ArtifactView, wanted: dict[str, str]) -> dict[str, str]:
    """Every wanted digest in one pass (sha256 is already known)."""
    out = {"sha256": view.sha256} if view.sha256 and "sha256" in wanted else {}
    pending = {
        name: hashlib.new(name, usedforsecurity=name != "md5" and name != "sha1")
        for name in wanted
        if name not in out
    }
    if pending:
        with view.open() as stream:
            while block := stream.read(1 << 20):
                for digest in pending.values():
                    digest.update(block)
        out |= {name: digest.hexdigest() for name, digest in pending.items()}
    return {k: v for k, v in out.items() if v}


def _glance_verify(
    key: object, key_type: str, signature: bytes, digest: bytes, algorithm: hashes.HashAlgorithm
) -> bool:
    prehashed = utils.Prehashed(algorithm)
    try:
        if isinstance(key, rsa.RSAPublicKey) and key_type.upper() == "RSA-PSS":
            key.verify(
                signature,
                digest,
                padding.PSS(mgf=padding.MGF1(algorithm), salt_length=padding.PSS.AUTO),
                prehashed,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey) and key_type.upper().startswith("ECC"):
            key.verify(signature, digest, ec.ECDSA(prehashed))
        elif isinstance(key, dsa.DSAPublicKey) and key_type.upper() == "DSA":
            key.verify(signature, digest, prehashed)
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


def _glance_summary(properties: dict[str, object]) -> dict[str, object]:
    keys = (
        "name",
        "disk_format",
        "container_format",
        "os_distro",
        "os_version",
        "os_hash_algo",
        "min_disk",
        "min_ram",
        "architecture",
        "img_signature_certificate_uuid",
        "visibility",
    )
    summary = {k: properties[k] for k in keys if k in properties}
    summary["hardware"] = {k: v for k, v in sorted(properties.items()) if k.startswith("hw_")}
    summary["signed"] = bool(properties.get("img_signature"))
    return summary


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(element: ET.Element, name: str) -> str | None:
    for key, value in element.attrib.items():
        if _local(key) == name:
            return value
    return None


@dataclass(slots=True)
class Ovf:
    files: list[dict[str, Any]] = field(default_factory=list)  # {"href", "size"}
    disks: list[dict[str, Any]] = field(default_factory=list)
    os: dict[str, Any] | None = None
    system: str | None = None


def _parse_ovf(data: bytes) -> Ovf:
    root = ET.fromstring(data)  # noqa: S314 - see the import
    ovf = Ovf()
    for element in root.iter():
        tag = _local(element.tag)
        if tag == "File":
            size = _attr(element, "size")
            ovf.files.append(
                {
                    "href": _attr(element, "href") or "",
                    "size": int(size) if size and size.isdigit() else None,
                }
            )
        elif tag == "Disk":
            ovf.disks.append(
                {
                    "capacity": _attr(element, "capacity"),
                    "units": _attr(element, "capacityAllocationUnits"),
                    "format": _attr(element, "format"),
                }
            )
        elif tag == "OperatingSystemSection":
            description = next((c.text for c in element if _local(c.tag) == "Description"), None)
            ovf.os = {
                "id": _attr(element, "id"),
                "description": (description or "").strip() or None,
            }
        elif tag == "VirtualSystem" and ovf.system is None:
            ovf.system = _attr(element, "id")
    return ovf


def _appliance_findings(
    ref: ArtifactRef,
    ctx: Context,
    missing: list[dict[str, object]],
    wrong_size: list[dict[str, object]],
) -> None:
    subject = Subject.of_artifact(ref)
    if missing:
        ctx.recorder.fail(
            "vm.image.incomplete",
            subject,
            tool=TOOL,
            detail={
                "format": "ovf",
                "dependsOn": [{"kind": "referenced file", "name": f["href"]} for f in missing],
            },
        )
    if wrong_size:
        ctx.recorder.fail(
            "vm.metadata.mismatch",
            subject,
            tool=TOOL,
            detail={
                "metadata": "OVF descriptor",
                "problems": [
                    {"field": f"size of {f['href']}", "declared": f.get("size")} for f in wrong_size
                ],
            },
        )
