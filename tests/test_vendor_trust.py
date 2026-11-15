"""Vendor trust: OpenPGP, RPM and Debian packages, RPM databases, checksum lists, detached
signatures. Keys and packages are generated in ``tests/vendor_fixtures.py``."""

import hashlib
from pathlib import Path

import pytest

from airlock.core.model import Result, TrustLevel, Verdict
from airlock.formats import openpgp
from airlock.formats.deb import deb_vercmp
from airlock.formats.rpm import compare_evr, rpm_vercmp
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import write
from tests.vendor_fixtures import PGPKey, RPMSpec, deb_bytes, rpm_bytes, rpmdb_bytes

RSA = PGPKey("rsa")
ED = PGPKey()


def _policy(tmp: Path, *anchors: tuple[str, PGPKey, str]) -> str:
    """anchors: (name, key, scope glob)."""
    tmp.mkdir(parents=True, exist_ok=True)
    lines = ["trust:", "  upstream:"]
    for name, key, scope in anchors:
        data = key.public()
        path = tmp / f"{name}.asc"
        path.write_bytes(data)
        lines += [
            f"    - name: {name}",
            "      type: gpg",
            f"      file: {path.as_posix()}",
            f'      sha256: "{hashlib.sha256(data).hexdigest()}"',
            f'      scope: ["{scope}"]',
        ]
    return "\n".join(lines) + "\n"


# --- OpenPGP ------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", [RSA, ED], ids=["rsa", "ed25519"])
def test_openpgp_detached_and_clearsigned(key: PGPKey) -> None:
    [public] = openpgp.load_keys(key.public())
    assert public.fingerprint == key.fingerprint.hex().upper()
    data = b"some release\n"
    assert openpgp.verify_detached(key.detached(data), data, [public]).valid
    assert openpgp.verify_detached(key.detached(data, armored=False), data, [public]).valid
    tampered = openpgp.verify_detached(key.detached(data), data + b"x", [public])
    assert not tampered.valid and tampered.key is public
    stranger = openpgp.load_keys(PGPKey().public())
    assert openpgp.verify_detached(key.detached(data), data, stranger).key is None

    text = "Origin: Example\n-dash line\ntrailing space   \nlast"
    result, signed = openpgp.verify_clearsigned(key.clearsign(text), [public])
    assert result.valid, result.reason
    assert signed.decode().splitlines()[1] == "-dash line"


def test_openpgp_refuses_weak_hashes() -> None:
    [public] = openpgp.load_keys(ED.public())
    result = openpgp.verify_detached(ED.detached(b"x", hash_algo=2), b"x", [public])
    assert not result.valid and "SHA-1" in result.reason


# --- RPM ----------------------------------------------------------------------------------------


def test_signed_rpm_verified_with_pinned_key(tmp_path: Path) -> None:
    root = write(tmp_path / "d", {"Packages/tinytool.rpm": rpm_bytes(RSA_SPEC, RSA)})
    result = inspect(root, policy_yaml=_policy(tmp_path / "k", ("vendor", RSA, "package.rpm")))
    found = findings_of(result)
    for rule in ("package.digest-mismatch", "package.signature.invalid",
                 "package.signature.untrusted", "package.signature.missing"):  # fmt: skip
        assert rule not in found, found.get(rule)
    [scripts] = found["package.maintainer-scripts"]
    assert scripts.detail["scripts"] == ["postin"]
    package = artifact(result, "Packages/tinytool.rpm")
    [check] = package.verifications
    assert (check.level, check.anchor, check.result) == (
        TrustLevel.SIGNATURE,
        "vendor",
        Result.PASS,
    )
    rpm = package.metadata["rpm"]
    assert (rpm["name"], rpm["evr"], rpm["vendor"]) == ("tinytool", "1:1.2-3.el9", "Example Linux")
    [component] = [c for c in result.analysis.components if c.name == "tinytool"]
    assert component.purl == "pkg:rpm/example/tinytool@1.2-3.el9?arch=x86_64&epoch=1"
    assert component.licenses[0].name == "MIT"


RSA_SPEC = RPMSpec(epoch=1)


def test_rpm_tampering_is_final(tmp_path: Path) -> None:
    good = rpm_bytes(RPMSpec(), RSA)
    header_edit = good.replace(b"Example Linux", b"Example Linus")
    files = {
        "payload.rpm": rpm_bytes(RPMSpec(), RSA, payload=b"something else"),
        "header.rpm": header_edit,
    }
    policy = _policy(tmp_path / "k", ("vendor", RSA, "package.rpm"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    found = findings_of(result)
    mismatched = {f.subject.display: f for f in found["package.digest-mismatch"]}
    assert "payload" in str(mismatched["payload.rpm"].detail)
    assert "header" in str(mismatched["header.rpm"].detail)
    [invalid] = found["package.signature.invalid"]
    assert invalid.subject.display == "header.rpm"
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_rpm_unsigned_untrusted_and_out_of_scope(tmp_path: Path) -> None:
    files = {"unsigned.rpm": rpm_bytes(RPMSpec(), None), "other.rpm": rpm_bytes(RPMSpec(), ED)}
    # The ED key is pinned, but only for apt repositories: it may not vouch for an RPM.
    policy = _policy(tmp_path / "k", ("vendor", RSA, "package.rpm"), ("archive", ED, "repo.apt"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    found = findings_of(result)
    [missing] = found["package.signature.missing"]
    assert missing.subject.display == "unsigned.rpm"
    [untrusted] = found["package.signature.untrusted"]
    assert untrusted.subject.display == "other.rpm"
    assert "package.signature.invalid" not in found
    assert not artifact(result, "other.rpm").verifications


def test_rpm_database_lists_installed_packages(tmp_path: Path) -> None:
    db = rpmdb_bytes([RPMSpec(), RPMSpec(name="bash", version="5.1.8", release="9.el9")], tmp_path)
    result = inspect(write(tmp_path / "d", {"rootfs/var/lib/rpm/rpmdb.sqlite": db}))
    rpmdb = artifact(result, "rootfs/var/lib/rpm/rpmdb.sqlite")
    assert rpmdb.kind == "os.rpmdb"
    assert rpmdb.metadata["osPackages"] == {"packages": 2}
    purls = sorted(c.purl or "" for c in result.analysis.components)
    assert purls == [
        "pkg:rpm/example/bash@5.1.8-9.el9?arch=x86_64",
        "pkg:rpm/example/tinytool@1.2-3.el9?arch=x86_64",
    ]


# --- Debian -------------------------------------------------------------------------------------


def test_deb_identity_and_maintainer_scripts(tmp_path: Path) -> None:
    files = {
        "pool/hello_2.10-3_amd64.deb": deb_bytes(),
        "pool/quiet_1.0_all.deb": deb_bytes("quiet", "1.0", "all", scripts={}),
        "pool/broken_0.1-1_amd64.deb": deb_bytes(control=False),
    }
    result = inspect(write(tmp_path / "d", files))
    found = findings_of(result)
    [scripts] = [f for f in found["package.maintainer-scripts"] if f.result is Result.FAIL]
    assert scripts.subject.display == "pool/hello_2.10-3_amd64.deb"
    assert scripts.detail["scripts"] == ["postinst"]
    deb = artifact(result, "pool/hello_2.10-3_amd64.deb").metadata["deb"]
    assert deb["Depends"] == "libc6 (>= 2.34)"
    # Unreadable control archive: identity from the file name, scripts not assessed.
    broken = artifact(result, "pool/broken_0.1-1_amd64.deb").metadata["deb"]
    assert (broken["name"], broken["version"]) == ("broken", "0.1-1")
    not_assessed = [
        f
        for f in result.assessment.findings
        if f.rule == "package.maintainer-scripts" and f.result is Result.NOT_ASSESSED
    ]
    assert [f.subject.display for f in not_assessed] == ["pool/broken_0.1-1_amd64.deb"]
    purls = sorted(c.purl or "" for c in result.analysis.components)
    assert "pkg:deb/debian/hello@2.10-3?arch=amd64" in purls
    assert "pkg:deb/debian/broken@0.1-1?arch=amd64" in purls


# --- checksum lists and detached signatures -----------------------------------------------------


def test_signed_checksum_list(tmp_path: Path) -> None:
    iso = b"an installer image"
    driver = b"a driver"
    sums = (
        f"{hashlib.sha256(iso).hexdigest()}  installer.iso\n"
        f"{hashlib.sha256(b'not the driver').hexdigest()} *driver.run\n"
        f"{hashlib.sha256(b'absent').hexdigest()}  not-shipped.iso\n"
    ).encode()
    files = {
        "media/installer.iso": iso,
        "media/driver.run": driver,
        "media/SHA256SUMS": sums,
        "media/SHA256SUMS.gpg": ED.detached(sums, armored=False),
    }
    policy = _policy(tmp_path / "k", ("publisher", ED, "file.*"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    found = findings_of(result)
    [mismatch] = found["upstream.checksum-mismatch"]
    assert mismatch.subject.display == "media/driver.run"
    assert mismatch.detail["list"] == "SHA256SUMS"
    assert result.assessment.summary.verdict is Verdict.REFUSED
    [check] = artifact(result, "media/installer.iso").verifications
    assert (check.level, check.anchor) == (TrustLevel.SIGNATURE, "publisher")
    summary = artifact(result, "media/SHA256SUMS").metadata["checksumList"]
    assert summary == {"listed": 3, "checked": 2, "signed": True}
    assert artifact(result, "media/SHA256SUMS.gpg").kind != "upstream.signature"


def test_clearsigned_bsd_list_and_unpinned_signer(tmp_path: Path) -> None:
    image = b"a cloud image"
    text = f"# Example-Cloud\nSHA256 (cloud.qcow2) = {hashlib.sha256(image).hexdigest()}\n"
    files = {"a/cloud.qcow2": image, "a/Example-CHECKSUM": ED.clearsign(text)}
    files |= {"b/cloud.qcow2": image, "b/Example-CHECKSUM": RSA.clearsign(text)}
    policy = _policy(tmp_path / "k", ("publisher", ED, "file.checksums"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    [signed] = artifact(result, "a/cloud.qcow2").verifications
    assert signed.level is TrustLevel.SIGNATURE
    # Signed by a key nobody pinned: the list still counts as a checksum that travelled along.
    [listed] = artifact(result, "b/cloud.qcow2").verifications
    assert (listed.level, listed.anchor) == (TrustLevel.CHECKSUM, "Example-CHECKSUM")
    [untrusted] = findings_of(result)["upstream.signature.untrusted"]
    assert untrusted.subject.display == "b/Example-CHECKSUM"


def test_detached_signatures(tmp_path: Path) -> None:
    tool = b"#!/bin/sh\necho tool\n"
    files = {
        "good/tool.sh": tool,
        "good/tool.sh.asc": ED.detached(tool),
        "bad/tool.sh": tool + b"rm -rf /\n",
        "bad/tool.sh.asc": ED.detached(tool),
        "stranger/tool.sh": tool,
        "stranger/tool.sh.sig": RSA.detached(tool, armored=False),
    }
    policy = _policy(tmp_path / "k", ("publisher", ED, "file.signed"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    [check] = artifact(result, "good/tool.sh").verifications
    assert (check.level, check.anchor) == (TrustLevel.SIGNATURE, "publisher")
    found = findings_of(result)
    [invalid] = found["upstream.signature.invalid"]
    assert invalid.subject.display == "bad/tool.sh.asc"
    [untrusted] = found["upstream.signature.untrusted"]
    assert untrusted.subject.display == "stranger/tool.sh.sig"
    assert result.assessment.summary.verdict is Verdict.REFUSED


# --- version ordering ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0", 0),
        ("1.0", "1.0.1", -1),
        ("1.0~rc1", "1.0", -1),
        ("1.0a", "1.0", 1),
        ("1.10", "1.9", 1),
        ("2.0^20240101", "2.0", 1),
        ("1.01", "1.1", 0),
    ],
)
def test_rpm_vercmp(a: str, b: str, expected: int) -> None:
    assert rpm_vercmp(a, b) == expected
    assert rpm_vercmp(b, a) == -expected


def test_compare_evr_epoch_wins() -> None:
    assert compare_evr("1:1.0-1", "2.0-1") == 1
    assert compare_evr("1.0-2.el9", "1.0-10.el9") == -1


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0", 0),
        ("1.0~rc1", "1.0", -1),
        ("1.0-1ubuntu1", "1.0-1", 1),
        ("1:0.9", "2.0", 1),
        ("2.10-3build1", "2.10-3", 1),
        ("1.0+dfsg-1", "1.0-1", 1),
    ],
)
def test_deb_vercmp(a: str, b: str, expected: int) -> None:
    assert deb_vercmp(a, b) == expected
    assert deb_vercmp(b, a) == -expected
