"""VM images and appliances: disk formats, dependencies, encryption, unclean state, OVA/OVF and
their manifests, Glance metadata and signatures, and the qemu-img plugin."""

import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from airlock.core.model import Result, TrustLevel, Verdict
from airlock.scanners.base import Completed
from tests.helpers import NOW
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import write
from tests.test_scanners import FakeTools, _binary
from tests.vm_fixtures import (
    MIB,
    iso,
    ovf,
    qcow2,
    raw_gpt,
    raw_mbr,
    tar,
    vhd_differencing,
    vhd_fixed,
    vhdx,
    vmdk_descriptor,
    vmdk_sparse,
)

LUKS_PARTITION = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
EFI = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def _failing(result, rule: str) -> dict[str, dict]:  # type: ignore[no-untyped-def,type-arg]
    return {
        f.subject.display: dict(f.detail)
        for f in findings_of(result).get(rule, [])
        if f.result is Result.FAIL
    }


def _image(result, path: str) -> dict:  # type: ignore[no-untyped-def,type-arg]
    image = artifact(result, path).metadata["vmImage"]
    assert isinstance(image, dict)
    return image


def test_disk_formats_and_their_problems(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "clean.qcow2": qcow2(size=64 * MIB),
        "linked.qcow2": qcow2(
            backing="/var/lib/libvirt/images/base.qcow2", incompatible=1, snapshots=2
        ),
        "locked.qcow2": qcow2(crypt=2),
        "split.qcow2": qcow2(data_file="/srv/data/disk.raw"),
        "old.qcow2": qcow2(version=2),
        "flat.vmdk": vmdk_descriptor(),
        "child.vmdk": vmdk_descriptor(extent="child-flat.vmdk", parent="C:\\VMs\\base.vmdk"),
        "child-flat.vmdk": b"\x00" * 512,
        "stream.vmdk": vmdk_sparse(unclean=True, name="stream.vmdk"),
        "fixed.vhd": vhd_fixed(),
        "broken.vhd": vhd_fixed(break_checksum=True),
        "delta.vhd": vhd_differencing("base.vhd"),
        "plain.vhdx": vhdx(size=16 * MIB),
        "delta.vhdx": vhdx(parent="..\\base.vhdx", dirty=True),
        "gpt.img": raw_gpt([EFI, LUKS_PARTITION]),
        "mbr.raw": raw_mbr(),
        "install.iso": iso(),
    }
    result = inspect(write(tmp_path / "d", files))
    clean = _image(result, "clean.qcow2")
    assert (clean["format"], clean["version"], clean["virtualSize"]) == ("qcow2", "v3", 64 * MIB)
    assert _image(result, "old.qcow2")["version"] == "v2"
    incomplete = _failing(result, "vm.image.incomplete")
    assert incomplete["linked.qcow2"]["dependsOn"] == [
        {"kind": "backing file", "name": "/var/lib/libvirt/images/base.qcow2"}
    ]
    assert incomplete["split.qcow2"]["dependsOn"] == [
        {"kind": "external data file", "name": "/srv/data/disk.raw"}
    ]
    assert incomplete["flat.vmdk"]["dependsOn"] == [{"kind": "extent", "name": "disk-flat.vmdk"}]
    assert incomplete["child.vmdk"]["dependsOn"] == [
        {"kind": "parent disk", "name": "C:\\VMs\\base.vmdk"}
    ]
    assert incomplete["delta.vhd"]["dependsOn"] == [{"kind": "parent disk", "name": "base.vhd"}]
    assert incomplete["delta.vhdx"]["dependsOn"] == [
        {"kind": "parent disk", "name": "..\\base.vhdx"}
    ]
    assert set(incomplete) == {
        "linked.qcow2",
        "split.qcow2",
        "flat.vmdk",
        "child.vmdk",
        "delta.vhd",
        "delta.vhdx",
    }
    unclean = _failing(result, "vm.image.unclean")
    assert unclean["linked.qcow2"]["state"] == ["dirty"]
    assert unclean["stream.vmdk"]["state"] == ["unclean shutdown"]
    assert unclean["broken.vhd"]["state"] == ["footer checksum mismatch"]
    assert unclean["delta.vhdx"]["state"] == ["log not replayed"]
    assert _failing(result, "vm.image.snapshots") == {"linked.qcow2": {"snapshots": 2}}
    encrypted = _failing(result, "vm.image.encrypted")
    assert encrypted == {
        "locked.qcow2": {"encryption": "luks"},
        "gpt.img": {"encryption": "luks-partition"},
    }
    assert _image(result, "plain.vhdx")["virtualSize"] == 16 * MIB
    assert _image(result, "stream.vmdk")["virtualSize"] == 4096 * 512
    assert [p["type"] for p in _image(result, "gpt.img")["partitions"]] == [
        "efi-system",
        "linux-luks",
    ]
    assert _image(result, "mbr.raw")["partitions"] == [{"type": "linux", "bytes": 6 * 512}]
    disc = _image(result, "install.iso")
    assert (disc["volumeId"], disc["bootable"]) == ("TEST_DISC", True)
    contents = [
        f
        for f in result.assessment.findings
        if f.rule == "vm.image.contents" and f.result is Result.NOT_ASSESSED
    ]
    reasons = {f.subject.display: f.not_assessed_reason or "" for f in contents}
    assert "encrypted" in reasons["locked.qcow2"] and "never mounted" in reasons["clean.qcow2"]
    units = {u.root.display: u for u in result.analysis.units if u.kind.value == "vm-image"}
    assert units["clean.qcow2"].attributes["format"] == "qcow2"
    assert result.assessment.summary.verdict is not Verdict.PASSED


def test_format_confusion(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {"disk.raw": qcow2(backing="/etc/shadow"), "disk.vhd": qcow2()}
    result = inspect(write(tmp_path / "d", files))
    mismatch = _failing(result, "vm.format.mismatch")
    assert mismatch["disk.raw"] == {"declared": "raw", "declaredBy": "file name", "actual": "qcow2"}
    assert mismatch["disk.vhd"]["actual"] == "qcow2"
    assert "disk.raw" in _failing(result, "vm.image.incomplete")


def test_ova_and_ovf_manifests(tmp_path: Path) -> None:
    disk = vmdk_sparse(name="appliance-disk1.vmdk")
    descriptor = ovf({"appliance-disk1.vmdk": len(disk), "appliance-disk2.vmdk": None})
    manifest = (
        f"SHA256(appliance.ovf)= {hashlib.sha256(descriptor).hexdigest()}\n"
        f"SHA256(appliance-disk1.vmdk)= {hashlib.sha256(b'not the disk').hexdigest()}\n"
    ).encode()
    ova = tar({"appliance.ovf": descriptor, "appliance.mf": manifest, "appliance-disk1.vmdk": disk})
    good_descriptor = ovf({"exported-disk1.vmdk": len(disk)})
    files: dict[str, bytes | str] = {
        "appliance.ova": ova,
        "export/exported.ovf": good_descriptor,
        "export/exported-disk1.vmdk": disk,
        "export/exported.mf": (
            f"SHA1(exported.ovf)= {hashlib.sha1(good_descriptor).hexdigest()}\n"  # noqa: S324
            f"SHA256(exported-disk1.vmdk)= {hashlib.sha256(disk).hexdigest()}\n"
        ),
    }
    result = inspect(write(tmp_path / "d", files))
    meta = artifact(result, "appliance.ova").metadata["vmAppliance"]
    assert (meta["manifest"], meta["manifestVerified"], meta["os"]["description"]) == (
        True,
        False,
        "Ubuntu 64-bit",
    )
    assert list(_failing(result, "upstream.checksum-mismatch")) == [
        "appliance.ova!/appliance-disk1.vmdk"
    ]
    assert _failing(result, "vm.image.incomplete")["appliance.ova"]["dependsOn"] == [
        {"kind": "referenced file", "name": "appliance-disk2.vmdk"}
    ]
    assert (
        artifact(result, "appliance.ova!/appliance.ovf").verifications[0].level
        is TrustLevel.CHECKSUM
    )
    # the unpacked export is complete and matches its manifest
    assert artifact(result, "export/exported-disk1.vmdk").verifications[0].type == "ovf-manifest"
    assert "export/exported.ovf" not in _failing(result, "vm.image.incomplete")
    nested = _image(result, "appliance.ova!/appliance-disk1.vmdk")
    assert nested["createType"] == "streamOptimized"


def _signed_glance(tmp_path: Path, image: bytes) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "image signer")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    signature = key.sign(
        image,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    path = tmp_path / "keys" / "glance.pem"
    path.parent.mkdir(parents=True)
    path.write_bytes(pem)
    policy = (
        "trust:\n  upstream:\n    - name: image-signing\n      type: x509\n"
        f'      file: {path.as_posix()}\n      sha256: "{hashlib.sha256(pem).hexdigest()}"\n'
        "      scope: [vm.glance]\n"
    )
    return policy, base64.b64encode(signature).decode()


def test_glance_metadata(tmp_path: Path) -> None:
    image = qcow2(size=128 * MIB)
    policy, signature = _signed_glance(tmp_path, image)

    def glance(**extra: object) -> str:
        return json.dumps(
            {
                "disk_format": "qcow2",
                "container_format": "bare",
                "os_hash_algo": "sha512",
                "os_hash_value": hashlib.sha512(image).hexdigest(),
                "checksum": hashlib.md5(image, usedforsecurity=False).hexdigest(),
                "size": len(image),
                "properties": {"os_distro": "ubuntu", "hw_firmware_type": "uefi"},
                **extra,
            }
        )

    files: dict[str, bytes | str] = {
        "good/ubuntu.qcow2": image,
        "good/ubuntu.qcow2.json": glance(
            img_signature=signature,
            img_signature_hash_method="SHA-256",
            img_signature_key_type="RSA-PSS",
            img_signature_certificate_uuid="5c4d9b0e-0000-4000-8000-000000000000",
        ),
        "bad/ubuntu.qcow2": image + b"\x00",
        "bad/ubuntu.json": glance(
            disk_format="raw",
            img_signature=signature,
            img_signature_hash_method="SHA-256",
            img_signature_key_type="RSA-PSS",
        ),
    }
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    levels = {(v.type, v.level) for v in artifact(result, "good/ubuntu.qcow2").verifications}
    assert levels == {("glance", TrustLevel.CHECKSUM), ("glance-signature", TrustLevel.SIGNATURE)}
    [unit] = [u for u in result.analysis.units if u.root.display == "good/ubuntu.qcow2"]
    assert unit.attributes["glance"]["os_distro"] == "ubuntu"
    assert unit.attributes["glance"]["hardware"] == {"hw_firmware_type": "uefi"}
    problems = _failing(result, "vm.metadata.mismatch")["bad/ubuntu.qcow2"]["problems"]
    assert {p["field"] for p in problems} == {"os_hash_value", "checksum", "size"}
    assert _failing(result, "vm.format.mismatch")["bad/ubuntu.qcow2"]["declared"] == "raw"
    assert list(_failing(result, "upstream.signature.invalid")) == ["bad/ubuntu.json"]
    assert result.assessment.summary.verdict is Verdict.REFUSED


@pytest.mark.parametrize("configured", [False, True])
def test_qemu_img_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured: bool) -> None:
    files: dict[str, bytes | str] = {
        "a.qcow2": qcow2(size=64 * MIB),
        "b.qcow2": qcow2(size=64 * MIB),
    }
    policy = ""
    if configured:
        tools = FakeTools(monkeypatch)
        binary, digest = _binary(tmp_path / "tools", "qemu-img")

        def qemu(args: list[str]) -> Completed:
            if args == ["--version"]:
                return Completed(0, "qemu-img version 8.2.2 (Debian 1:8.2.2)\n", "")
            path = args[-1]
            if args[0] == "info":
                size = 64 * MIB if path.endswith("a.qcow2") else 32 * MIB
                return Completed(
                    0,
                    json.dumps({"format": "qcow2", "virtual-size": size, "dirty-flag": False}),
                    "",
                )
            leaks = 3 if path.endswith("b.qcow2") else 0
            return Completed(3 if leaks else 0, json.dumps({"leaks": leaks, "check-errors": 0}), "")

        tools.handlers["qemu-img"] = qemu  # type: ignore[assignment]
        policy = (
            f"plugins:\n  qemu-img:\n    path: {binary.as_posix()}\n    binarySha256: {digest}\n"
        )
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy, plugins=True)
    checks = [f for f in result.assessment.findings if f.rule == "vm.image.check"]
    if not configured:
        [gap] = checks
        assert gap.result is Result.NOT_ASSESSED and "qemu-img" in (gap.not_assessed_reason or "")
        return
    assert all("-f" in c and "qcow2" in c and "-U" in c for c in tools.commands("qemu-img")[1:])
    [failed] = [f for f in checks if f.result is Result.FAIL]
    assert failed.subject.display == "b.qcow2"
    assert failed.detail["problems"] == [
        f"virtual size: airlock read {64 * MIB}, qemu-img {32 * MIB}",
        "leaks: 3",
    ]
