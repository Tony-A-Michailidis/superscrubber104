"""Damaged or hostile vendor artefacts, mirrors, packages, infrastructure code and VM images
produce findings, never handler crashes; and the limits that keep them from exhausting the host.

Every sample here is cut short at several points and has bytes flipped. A handler that raises is
reported as ``inventory.handler.error``; none may be.
"""

import gzip
import hashlib
import io
import json
import random
import zipfile
from pathlib import Path

import pytest

from airlock.archive import ZSTD, ExpansionLimit, capped
from airlock.formats import openpgp
from airlock.formats.deb import DebError, read_deb
from airlock.formats.golang import ZipHashError, zip_hash
from tests import vm_fixtures as vm
from tests.hauler_fixtures import haul, haul_bytes
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import write
from tests.test_ecosystems import _crate, _jar, _module, _nupkg, _zip
from tests.test_iac import DEPLOYMENT
from tests.test_ide import _manifest, _vsix
from tests.vendor_fixtures import (
    PGPKey,
    RPMSpec,
    _ar,
    deb_bytes,
    packages_index,
    primary_xml,
    release_text,
    repomd_xml,
    rpm_bytes,
)
from tests.zarf_fixtures import NAME as ZARF_NAME
from tests.zarf_fixtures import KeySigner, build, package_bytes, tar

ED = PGPKey()
RPM = rpm_bytes(RPMSpec(), ED, package_signature=True)
DEB = deb_bytes()
PRIMARY = gzip.compress(primary_xml({"Packages/a.rpm": ("a", RPM)}), mtime=0)
REPOMD = repomd_xml({"primary": ("repodata/1-primary.xml.gz", PRIMARY)})
PACKAGES = packages_index({"pool/h/hello.deb": ("hello", "1", DEB)}).encode()
RELEASE = release_text(
    {"main/binary-amd64/Packages": PACKAGES}, date="Sun, 08 Nov 2026 00:00:00 UTC"
)
MODULE_ZIP, MODULE_MOD = _module("example.com/m", "v1.0.0")
DISK = vm.vmdk_sparse(name="d.vmdk")
OVF = vm.ovf({"d.vmdk": len(DISK)})
MANIFEST = f"SHA256(a.ovf)= {hashlib.sha256(OVF).hexdigest()}\n".encode()
CHART = (
    b"apiVersion: v2\nname: a\nversion: 1.0.0\n"
    b"dependencies:\n  - {name: r, version: 1.0.0, repository: 'https://x'}\n"
)
COMPOSE = (
    b"x-a: &a {image: 'x:1'}\nservices:\n  s:\n    <<: *a\n    privileged: true\n"
    b"    volumes: ['/var/run/docker.sock:/s', {type: bind, source: /etc}]\n"
)
PACKUMENT = json.dumps(
    {
        "_id": "t",
        "name": "t",
        "dist-tags": {},
        "versions": {"1.0.0": {"dist": {"tarball": "t-1.0.0.tgz", "integrity": "sha512-AA=="}}},
    }
).encode()
GLANCE = json.dumps(
    {
        "disk_format": "qcow2",
        "checksum": "00",
        "os_hash_algo": "sha512",
        "os_hash_value": "00",
        "img_signature": "AAAA",
        "img_signature_hash_method": "SHA-256",
        "img_signature_key_type": "RSA-PSS",
    }
).encode()

# name -> (path of the damaged file, its bytes, files beside it that stay intact)
SAMPLES: dict[str, tuple[str, bytes, dict[str, bytes]]] = {
    "rpm": ("p/a.rpm", RPM, {}),
    "deb": ("p/a.deb", DEB, {}),
    "sums": (
        "k/SHA256SUMS",
        f"{hashlib.sha256(RPM).hexdigest()}  a.rpm\n".encode(),
        {"k/a.rpm": RPM},
    ),
    "sums-signature": (
        "k/SHA256SUMS.gpg",
        ED.detached(b"x", armored=False),
        {"k/SHA256SUMS": b"00  a\n"},
    ),
    "clearsigned": ("k/CHECKSUM", ED.clearsign("SHA256 (a.rpm) = " + "0" * 64), {"k/a.rpm": RPM}),
    "detached": ("k/tool.sh.asc", ED.detached(b"tool"), {"k/tool.sh": b"tool"}),
    "repomd": ("repo/repodata/repomd.xml", REPOMD, {"repo/repodata/1-primary.xml.gz": PRIMARY}),
    "repomd-signature": (
        "repo/repodata/repomd.xml.asc",
        ED.detached(REPOMD),
        {"repo/repodata/repomd.xml": REPOMD},
    ),
    "primary": ("repo/repodata/1-primary.xml.gz", PRIMARY, {"repo/Packages/a.rpm": RPM}),
    "inrelease": (
        "apt/dists/s/InRelease",
        ED.clearsign(RELEASE),
        {"apt/dists/s/main/binary-amd64/Packages": PACKAGES},
    ),
    "apt-packages": (
        "apt/dists/s/main/binary-amd64/Packages",
        PACKAGES,
        {"apt/pool/h/hello.deb": DEB},
    ),
    "pypi": ("pypi/simple/x/index.html", b'<a href="../../packages/x-1.whl#sha256=00">x</a>', {}),
    "packument": ("npm/t/package.json", PACKUMENT, {"npm/t/t-1.0.0.tgz": b"x"}),
    "helm-index": (
        "charts/index.yaml",
        b"apiVersion: v1\nentries:\n  w:\n  - {version: 1.0.0, digest: '00', urls: [w-1.0.0.tgz]}\n",
        {"charts/w-1.0.0.tgz": b"x"},
    ),
    "helm-prov": (
        "charts/w-1.0.0.tgz.prov",
        ED.clearsign("files:\n  w-1.0.0.tgz: sha256:" + "0" * 64),
        {"charts/w-1.0.0.tgz": b"x"},
    ),
    "go-zip": ("go/pkg/mod/cache/download/example.com/m/@v/v1.0.0.zip", MODULE_ZIP, {}),
    "go-sum": (
        "app/go.sum",
        b"example.com/m v1.0.0 h1:AAAA=\nexample.com/m v1.0.0/go.mod h1:BBBB=\n",
        {},
    ),
    "crate": ("c/good-1.0.0.crate", _crate("good", "1.0.0", build=True), {}),
    "cargo-lock": (
        "c/Cargo.lock",
        b'version = 3\n[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "registry+x"\nchecksum = "00"\n',
        {},
    ),
    "cargo-vendored": (
        "c/vendor/v/.cargo-checksum.json",
        json.dumps({"files": {"src/lib.rs": "00"}, "package": "00"}).encode(),
        {"c/vendor/v/Cargo.toml": b'[package]\nname="v"\nversion="1.0.0"\n'},
    ),
    "nupkg": ("n/a.1.0.0.nupkg", _nupkg("A", "1.0", hooks=True), {}),
    "nuget-lock": (
        "n/packages.lock.json",
        json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {"A": {"type": "Direct", "resolved": "1.0.0", "contentHash": "AAAA"}}
                },
            }
        ).encode(),
        {},
    ),
    "jar": (
        "m2/org/example/lib/1.0.0/lib-1.0.0.jar",
        _jar("org.example", "lib", "1.0.0"),
        {"m2/org/example/lib/1.0.0/lib-1.0.0.jar.sha1": b"00"},
    ),
    "gradle-verification": (
        "j/gradle/verification-metadata.xml",
        b'<verification-metadata><components><component group="g" name="n" version="1"><artifact name="n-1.jar"><sha256 value="00"/></artifact></component></components></verification-metadata>',
        {},
    ),
    "kubernetes": ("k8s/app.yaml", DEPLOYMENT.encode(), {}),
    "compose": ("compose.yaml", COMPOSE, {}),
    "chart": (
        "chart/Chart.yaml",
        CHART,
        {"chart/Chart.lock": b"dependencies:\n  - {name: r, version: 1.0.0}\n"},
    ),
    "terraform-lock": (
        "tf/.terraform.lock.hcl",
        b'provider "registry.terraform.io/a/b" {\n  version = "1.0.0"\n  hashes = [\n    "h1:AA=",\n  ]\n}\n',
        {},
    ),
    "terraform-provider": (
        "mirror/registry.terraform.io/a/b/terraform-provider-b_1.0.0_linux_amd64.zip",
        _zip({"terraform-provider-b_v1.0.0": b"x"}),
        {},
    ),
    "ansible": (
        "ans/requirements.yml",
        b"collections:\n  - name: a.b\n    version: 1.0.0\nroles:\n  - name: r\n",
        {},
    ),
    "vsix": (
        "ext/a.vsix",
        _vsix(_manifest("a", activationEvents=["*"], extensionDependencies=["x.y"])),
        {},
    ),
    "jetbrains": (
        "plug/p.jar",
        _zip(
            {
                "META-INF/plugin.xml": b"<idea-plugin><id>a</id><version>1</version><depends>b</depends></idea-plugin>"
            }
        ),
        {},
    ),
    "qcow2": (
        "vm/a.qcow2",
        vm.qcow2(
            backing="/x/base.qcow2", data_file="/x/d.raw", incompatible=3, snapshots=1, crypt=2
        ),
        {},
    ),
    "vmdk-descriptor": ("vm/a.vmdk", vm.vmdk_descriptor(parent="p.vmdk").encode(), {}),
    "vmdk": ("vm/d.vmdk", DISK, {}),
    "vhd": ("vm/b.vhd", vm.vhd_differencing("p.vhd"), {}),
    "vhdx": ("vm/a.vhdx", vm.vhdx(parent="p.vhdx", dirty=True), {}),
    "gpt": ("vm/a.img", vm.raw_gpt(["C12A7328-F81F-11D2-BA4B-00A0C93EC93B"]), {}),
    "iso": ("vm/a.iso", vm.iso(), {}),
    "ova": ("vm/a.ova", vm.tar({"a.ovf": OVF, "a.mf": MANIFEST, "d.vmdk": DISK}), {}),
    "ovf": ("ovf/a.ovf", OVF, {"ovf/d.vmdk": DISK}),
    "glance": ("gl/a.qcow2.json", GLANCE, {"gl/a.qcow2": vm.qcow2()}),
    "zarf": (f"z/{ZARF_NAME}", package_bytes(build(signer=KeySigner())), {}),
    "zarf-odd-definition": (
        f"z/{ZARF_NAME}",
        tar(
            {
                "zarf.yaml": b"apiVersion: zarf.dev/v1beta1\nmetadata: []\n"
                b"build: {differential: {fromVersion: 3}, provenanceFiles: 7}\n"
                b"components: [1, {name: x, images: [{}, 2], files: [3, {target: 5}],"
                b" actions: {onDeploy: [1], onRemove: {before: [{cmd: 4}]}}}]\n",
                "checksums.txt": b"zz\nnot-hex x\n" + b"0" * 64 + b" ../../etc/passwd\n",
                "zarf.bundle.sig": b'{"messageSignature": {"signature": 5}}',
                "images/index.json": b'{"manifests": [1, {"annotations": 5, "digest": 3}]}',
                "components/x.tar": b"not a tar",
            }
        ),
        {},
    ),
    **(
        {"zarf-zstd": (f"z/{ZARF_NAME}.zst", package_bytes(build(), zstd=True), {})} if ZSTD else {}
    ),
    "haul": ("h/haul.tar", haul_bytes(haul()), {}),
    "haul-gzip": ("h/haul.tar.gz", haul_bytes(haul(), "gzip"), {}),
    "haul-odd-index": (
        "h/haul.tar",
        tar(
            {
                "oci-layout": b"{}",
                "index.json": b'{"manifests": [1, {"digest": "sha256:' + b"0" * 64 + b'", '
                b'"annotations": {"kind": "dev.hauler/sigs"}}, {"annotations": []}]}',
                "blobs/sha256/" + "0" * 64: b'{"layers": 5, "config": []}',
            }
        ),
        {},
    ),
    **({"haul-zstd": ("h/haul.tar.zst", haul_bytes(haul(), "zstd"), {})} if ZSTD else {}),
}


def _variants(data: bytes, rng: random.Random) -> list[bytes]:
    points = sorted({1, 4, 16, 64, 104, 257, 512, len(data) // 3, len(data) // 2, len(data) - 1})
    out = [data[:p] for p in points if 0 < p < len(data)]
    for flips in (1, 12, 40):
        damaged = bytearray(data)
        for _ in range(flips):
            index = rng.randrange(len(damaged))
            damaged[index] = rng.choice((0, 0xFF, damaged[index] ^ (1 << rng.randrange(8))))
        out.append(bytes(damaged))
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:200]):  # text: break its structure
        text = data.decode("utf-8", "replace")
        out += [text.replace(":", "").encode(), text.replace('"', "").encode(), b"[]", b"null"]
    return out


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_damaged_files_never_crash_a_handler(tmp_path: Path, name: str) -> None:
    path, data, beside = SAMPLES[name]
    rng = random.Random(name)
    for index, variant in enumerate(_variants(data, rng)):
        root = write(tmp_path / str(index), {**beside, path: variant})
        errors = findings_of(inspect(root)).get("inventory.handler.error", [])
        assert not errors, (name, index, [e.detail for e in errors])


# --- limits -------------------------------------------------------------------------------------


def test_capped_stream_refuses_to_expand() -> None:
    bomb = gzip.compress(b"\x00" * (4 << 20))
    assert len(bomb) < 8192
    with pytest.raises(ExpansionLimit):
        capped(gzip.GzipFile(fileobj=io.BytesIO(bomb)), 1 << 20).read()  # type: ignore[arg-type]
    assert capped(io.BytesIO(b"abc"), 3).read() == b"abc"


def test_deb_control_archive_bomb_is_refused() -> None:
    bomb = gzip.compress(b"\x00" * (32 << 20))  # expands past the 16 MiB a control archive may be
    package = _ar({"debian-binary": b"2.0\n", "control.tar.gz": bomb})
    with pytest.raises(DebError, match="expands beyond"):
        read_deb(io.BytesIO(package))


def test_zip_hash_limits() -> None:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("m@v1/big", b"\x00" * (2 << 20))
    with pytest.raises(ZipHashError, match="larger than"):
        zip_hash(io.BytesIO(out.getvalue()), limit=1 << 20)
    assert zip_hash(io.BytesIO(out.getvalue())).startswith("h1:")
    with pytest.raises(ZipHashError, match="unreadable"):
        zip_hash(io.BytesIO(b"PK\x03\x04 not a zip"))


# --- OpenPGP ------------------------------------------------------------------------------------


def _packets(signature: bytes) -> tuple[bytes, bytes, bytes]:
    """(hashed area with its 6-byte prefix, unhashed subpackets, the rest) of a v4 signature."""
    body = signature[6:]  # the fixtures write a 6-byte new-format packet header
    hashed_length = int.from_bytes(body[4:6], "big")
    hashed = body[: 6 + hashed_length]
    at = 6 + hashed_length
    unhashed_length = int.from_bytes(body[at : at + 2], "big")
    return hashed, body[at + 2 : at + 2 + unhashed_length], body[at + 2 + unhashed_length :]


def _rebuild(hashed: bytes, unhashed: bytes, rest: bytes) -> bytes:
    body = hashed + len(unhashed).to_bytes(2, "big") + unhashed + rest
    return bytes([0xC2, 255]) + len(body).to_bytes(4, "big") + body


def test_expiry_is_only_believed_from_the_signed_area() -> None:
    """Anyone can rewrite the unhashed area: a creation time or lifetime planted there must not
    change when the signature is taken to expire."""
    [key] = openpgp.load_keys(ED.public())
    hashed, unhashed, rest = _packets(ED.sign(b"data"))
    planted = bytes([5, 3]) + (10**9).to_bytes(4, "big")  # "expires in 31 years"
    [original] = openpgp.load_signatures(_rebuild(hashed, unhashed, rest))
    [tampered] = openpgp.load_signatures(_rebuild(hashed, unhashed + planted, rest))
    assert tampered.expires == original.expires
    assert openpgp.verify(tampered, [b"data"], [key]).valid  # the signed part is untouched


def test_malformed_openpgp_is_an_error_not_a_hang() -> None:
    hashed, unhashed, rest = _packets(ED.sign(b"data"))
    with pytest.raises(openpgp.OpenPGPError):  # a zero-length subpacket never advances
        openpgp.load_signatures(_rebuild(hashed, unhashed + b"\x00\x00", rest))
    for cut in (1, 3, 7, 12, 40):
        with pytest.raises(openpgp.OpenPGPError):
            openpgp.load_signatures(ED.sign(b"data")[:cut])
    assert openpgp.load_signatures(b"") == []


def test_unsupported_signatures_do_not_hide_a_readable_one() -> None:
    [key] = openpgp.load_keys(ED.public())
    good = ED.sign(b"data")
    version3 = bytes([0xC2, 255]) + (5).to_bytes(4, "big") + b"\x03\x05\x00\x00\x00"
    [signature] = openpgp.load_signatures(version3 + good)
    assert openpgp.verify(signature, [b"data"], [key]).valid
    with pytest.raises(openpgp.OpenPGPError, match="version 3"):
        openpgp.load_signatures(version3)


def test_clearsigned_text_mentioning_a_signature(tmp_path: Path) -> None:
    """The words that start the signature block may appear, dash-escaped, in the signed text."""
    [key] = openpgp.load_keys(ED.public())
    text = "first\n-----BEGIN PGP SIGNATURE-----\nlast"
    result, signed = openpgp.verify_clearsigned(ED.clearsign(text), [key])
    assert result.valid and signed.decode() == text
    damaged = ED.clearsign("x").replace(b"-----END PGP SIGNATURE-----", b"!!!")
    result, _ = openpgp.verify_clearsigned(damaged, [key])
    assert not result.valid
