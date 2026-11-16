"""Patch planning: inventories, feeds (OSV, updateinfo, MSRC CVRF, KEV), plans, confirmation, the
CLI, and the Authenticode plugin. Feeds were also checked against real snapshots: AlmaLinux 9
BaseOS updateinfo.xml, USN and ALSA OSV records, the November 2024 MSRC CVRF and CISA's KEV."""

import gzip
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from airlock.cli import main
from airlock.core.errors import ConfigError
from airlock.core.model import Result
from airlock.core.signing import generate_key
from airlock.feeds.readers import load_feed
from airlock.patch.inventory import (
    InstalledPackage,
    Inventory,
    OsIdentity,
    collect,
    from_windows,
    load,
    sign,
)
from airlock.patch.plan import confirm, markdown, plan
from airlock.scanners.base import Completed
from tests.helpers import NOW, make_site
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import write
from tests.test_scanners import FakeTools, _binary
from tests.vendor_fixtures import RPMSpec, rpmdb_bytes

ALMA = OsIdentity("rpm", "almalinux", "9.4", "AlmaLinux 9.4")


def _alma_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = rpmdb_bytes(
        [
            RPMSpec(name="openssl", version="3.0.7", release="24.el9", epoch=1),
            RPMSpec(name="kernel", version="5.14.0", release="427.13.1.el9_4"),
            RPMSpec(name="bash", version="5.1.8", release="9.el9"),
        ],
        tmp_path,
    )
    write(
        root,
        {
            "etc/os-release": 'NAME="AlmaLinux"\nID="almalinux"\nVERSION_ID="9.4"\nPRETTY_NAME="AlmaLinux 9.4"\n',
            "var/lib/rpm/rpmdb.sqlite": db,
            "sys/module/nvidia/version": "550.54.15\n",
            "usr/local/cuda/version.json": json.dumps({"cuda": {"version": "12.4.1"}}),
            "etc/hostname": "secret-host-name\n",
        },
    )
    return root


# --- inventory ----------------------------------------------------------------------------------


def test_inventory_from_an_rpm_root(tmp_path: Path) -> None:
    inventory = collect(_alma_root(tmp_path), "web-01", NOW)
    assert inventory.os == ALMA
    assert [(p.name, p.version, p.arch) for p in inventory.packages] == [
        ("bash", "5.1.8-9.el9", "x86_64"),
        ("kernel", "5.14.0-427.13.1.el9_4", "x86_64"),
        ("openssl", "1:3.0.7-24.el9", "x86_64"),
    ]
    assert inventory.components == {"nvidiaDriver": "550.54.15", "cuda": "12.4.1"}
    key = generate_key()
    path = tmp_path / "inv.json"
    path.write_bytes(sign(inventory, key))
    assert b"secret-host-name" not in path.read_bytes()
    loaded, signers = load(path, [key.verify_key])
    assert (loaded, signers) == (inventory, [key.key_id])
    tampered = json.loads(path.read_bytes())
    tampered["payload"] = tampered["payload"][:-8] + "AAAAAAA="
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ConfigError, match="does not verify"):
        load(path, [key.verify_key])
    with pytest.raises(ConfigError, match="label"):
        collect(_alma_root(tmp_path / "again"), "host name with spaces", NOW)


def test_inventory_from_dpkg_and_windows(tmp_path: Path) -> None:
    status = (
        "Package: libssl3t64\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.1\n"
        "Architecture: amd64\nSource: openssl\n\n"
        "Package: nano\nStatus: install ok installed\nVersion: 7.2-2build1\nArchitecture: amd64\n\n"
        "Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0\nArchitecture: amd64\n"
    )
    root = write(
        tmp_path / "u",
        {"etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\n', "var/lib/dpkg/status": status},
    )
    inventory = collect(root, "dev-02", NOW)
    assert inventory.os.family == "deb"
    assert [(p.name, p.source) for p in inventory.packages] == [
        ("libssl3t64", "openssl"),
        ("nano", None),
    ]
    hotfixes = tmp_path / "hotfix.json"
    hotfixes.write_text(
        json.dumps([{"HotFixID": "KB5041160"}, {"HotFixID": "kb5005112"}]), encoding="utf-8"
    )
    windows = from_windows(hotfixes, "Windows Server 2022", "10.0.20348.2700", "dc-01", NOW)
    assert [p.name for p in windows.packages] == ["KB5005112", "KB5041160"]


# --- feeds and plans ----------------------------------------------------------------------------


def _feeds(tmp_path: Path) -> dict[str, Path]:
    feeds = tmp_path / "feeds"
    feeds.mkdir(parents=True, exist_ok=True)
    updateinfo = """<?xml version="1.0"?><updates>
<update type="security"><id>ALSA-2026:0001</id><title>Important: openssl security update</title>
  <issued date="2026-10-01 00:00:00"/><severity>Important</severity>
  <references><reference type="cve" id="CVE-2026-1111"/></references>
  <pkglist><collection>
    <package name="openssl" version="3.0.7" release="27.el9" epoch="1" arch="x86_64"/>
    <package name="openssl" version="3.0.7" release="27.el9" epoch="1" arch="i686"/>
  </collection></pkglist></update>
<update type="security"><id>ALSA-2026:0002</id><title>Moderate: kernel update</title>
  <issued date="2026-11-01 00:00:00"/><severity>Moderate</severity>
  <references><reference type="cve" id="CVE-2026-2222"/></references>
  <pkglist><collection><package name="kernel" version="5.14.0" release="503.1.1.el9_5" epoch="0" arch="x86_64"/></collection></pkglist></update>
<update type="security"><id>ALSA-2026:0003</id><title>Low: bash update</title>
  <issued date="2026-11-02 00:00:00"/>
  <pkglist><collection><package name="bash" version="5.1.8" release="9.el9" epoch="0" arch="x86_64"/></collection></pkglist></update>
<update type="bugfix"><id>ALBA-2026:0004</id><title>bugfix</title>
  <pkglist><collection><package name="bash" version="9" release="1" epoch="0" arch="x86_64"/></collection></pkglist></update>
</updates>"""
    (feeds / "updateinfo.xml.gz").write_bytes(gzip.compress(updateinfo.encode(), mtime=0))
    kev = {
        "catalogVersion": "2026.11.09",
        "dateReleased": "2026-11-09T00:00:00Z",
        "vulnerabilities": [{"cveID": "CVE-2026-2222"}],
    }
    (feeds / "kev.json").write_text(json.dumps(kev), encoding="utf-8")
    osv = feeds / "osv"
    osv.mkdir(exist_ok=True)
    usn = {
        "id": "USN-9000-1",
        "summary": "openssl vulnerabilities",
        "modified": "2026-11-05T00:00:00Z",
        "published": "2026-11-04T00:00:00Z",
        "upstream": ["CVE-2026-3333"],
        "affected": [
            {
                "package": {
                    "name": "openssl",
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "purl": "pkg:deb/ubuntu/openssl?arch=source",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.4"}],
                    }
                ],
                "ecosystem_specific": {
                    "binaries": [{"binary_name": "libssl3t64"}, {"binary_name": "openssl"}]
                },
            },
            {
                "package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.18"}],
                    }
                ],
            },
        ],
    }
    (osv / "USN-9000-1.json").write_text(json.dumps(usn), encoding="utf-8")
    cvrf = {
        "DocumentTracking": {
            "Identification": {"ID": {"Value": "2026-Nov"}},
            "CurrentReleaseDate": "2026-11-10T08:00:00Z",
        },
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "1", "Value": "Windows Server 2022"},
                {"ProductID": "2", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
            ]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-4444",
                "Threats": [{"Type": 3, "Description": {"Value": "Critical"}, "ProductID": ["1"]}],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": "5050001"},
                        "ProductID": ["1"],
                        "Supercedence": "5040001",
                        "RestartRequired": {"Value": "Yes"},
                    },
                    {"Type": 2, "Description": {"Value": "5050009"}, "ProductID": ["2"]},
                ],
            },
            {
                "CVE": "CVE-2026-5555",
                "Threats": [{"Type": 3, "Description": {"Value": "Important"}}],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": "5040001"},
                        "ProductID": ["1"],
                        "Supercedence": "5030001",
                    }
                ],
            },
        ],
    }
    (feeds / "cvrf.json").write_text(json.dumps(cvrf), encoding="utf-8")
    return {
        "updateinfo": feeds / "updateinfo.xml.gz",
        "kev": feeds / "kev.json",
        "osv": osv,
        "cvrf": feeds / "cvrf.json",
    }


def _alma_inventory(**extra: str) -> Inventory:
    return Inventory(
        "web-01",
        NOW,
        ALMA,
        (
            InstalledPackage("bash", "5.1.8-9.el9", "x86_64"),
            InstalledPackage("kernel", "5.14.0-427.13.1.el9_4", "x86_64"),
            InstalledPackage("openssl", extra.get("openssl", "1:3.0.7-24.el9"), "x86_64"),
        ),
    )


def test_feed_readers(tmp_path: Path) -> None:
    paths = _feeds(tmp_path)
    updateinfo = load_feed(paths["updateinfo"])
    assert updateinfo.kind == "updateinfo"
    assert [a.id for a in updateinfo.advisories] == [
        "ALSA-2026:0001",
        "ALSA-2026:0002",
        "ALSA-2026:0003",
    ]
    assert updateinfo.advisories[0].fixes[0].fixed == "1:3.0.7-27.el9"
    assert load_feed(paths["kev"]).cves == frozenset({"CVE-2026-2222"})
    [usn] = load_feed(paths["osv"]).advisories
    assert (usn.fixes[0].source, usn.fixes[0].binaries, usn.cves) == (
        True,
        ("libssl3t64", "openssl"),
        ("CVE-2026-3333",),
    )
    cvrf = {a.id: a for a in load_feed(paths["cvrf"]).advisories}
    assert cvrf["KB5050001"].supersedes == ("KB5040001",)
    assert (cvrf["KB5050001"].severity, cvrf["KB5050001"].reboot) == ("critical", True)


def test_rpm_plan_and_emergency_filters(tmp_path: Path) -> None:
    paths = _feeds(tmp_path)
    feeds = [load_feed(paths["updateinfo"]), load_feed(paths["kev"])]
    result = plan(
        _alma_inventory(),
        feeds,
        NOW,
        max_age={"default": timedelta(days=30), "kev": timedelta(days=1)},
    )
    assert [g.advisory for g in result.gaps] == [
        "ALSA-2026:0002",
        "ALSA-2026:0001",
    ]  # KEV first; bash is current
    kernel, openssl = result.gaps
    assert (kernel.kev, kernel.reboot, kernel.age_days) == (True, True, 9)
    assert [(p.name, p.installed, p.fixed, p.arch) for p in openssl.packages] == [
        (
            "openssl",
            "1:3.0.7-24.el9",
            "1:3.0.7-27.el9",
            "x86_64",
        )  # the i686 fix is for another arch
    ]
    assert result.fetch == ("kernel-5.14.0-503.1.1.el9_5.x86_64", "openssl-3.0.7-27.el9.x86_64")
    assert result.stale_feeds == ["kev.json"]  # built 1.5 days ago, against a 1-day limit
    emergency = plan(_alma_inventory(), feeds, NOW, kev_only=True)
    assert [g.advisory for g in emergency.gaps] == ["ALSA-2026:0002"]
    assert emergency.filters == {"kev": "true"}
    by_cve = plan(_alma_inventory(), feeds, NOW, cves=["cve-2026-1111"])
    assert [g.advisory for g in by_cve.gaps] == ["ALSA-2026:0001"]
    text = markdown(result)
    assert "| ALSA-2026:0002 | moderate | yes | yes | 9 | CVE-2026-2222 |" in text
    assert "**Stale or unreadable feeds:** kev.json" in text


def test_deb_and_windows_plans(tmp_path: Path) -> None:
    paths = _feeds(tmp_path)
    ubuntu = Inventory(
        "dev-02",
        NOW,
        OsIdentity("deb", "ubuntu", "24.04"),
        (
            InstalledPackage("libssl3t64", "3.0.13-0ubuntu3.1", "amd64", "openssl"),
            InstalledPackage("libcrypt1", "1:4.4.36-4build1", "amd64", "libxcrypt"),
        ),
    )
    [gap] = plan(ubuntu, [load_feed(paths["osv"])], NOW).gaps
    assert [(p.name, p.fixed) for p in gap.packages] == [("libssl3t64", "3.0.13-0ubuntu3.4")]
    assert plan(ubuntu, [load_feed(paths["osv"])], NOW).fetch == ("libssl3t64=3.0.13-0ubuntu3.4",)

    windows = Inventory(
        "dc-01", NOW, OsIdentity("windows", "windows", "10.0.20348.2700", "Windows Server 2022"),
        (InstalledPackage("KB5030001", ""),),
    )  # fmt: skip
    result = plan(windows, [load_feed(paths["cvrf"])], NOW)
    # KB5040001 is missing too, but KB5050001 supersedes it: install the newer one only.
    assert [g.advisory for g in result.gaps] == ["KB5050001"]
    patched = Inventory(windows.label, NOW, windows.os, (InstalledPackage("KB5050001", ""),))
    assert plan(patched, [load_feed(paths["cvrf"])], NOW).gaps == ()


def test_confirm_shows_the_gap_closed(tmp_path: Path) -> None:
    paths = _feeds(tmp_path)
    feeds = [load_feed(paths["updateinfo"]), load_feed(paths["kev"])]
    before = plan(_alma_inventory(), feeds, NOW)
    after = _alma_inventory(openssl="1:3.0.7-27.el9")
    assert confirm(before, after, feeds, NOW) == {
        "closed": ["ALSA-2026:0001"],
        "open": ["ALSA-2026:0002"],
        "new": [],
    }


def test_patch_cli(tmp_path: Path) -> None:
    site = make_site(tmp_path / "site")
    key_file = tmp_path / "receipt.key"
    from airlock.core.signing import save_key

    save_key(site.receipt_key, key_file, tmp_path / "receipt.pub", None)
    policy = site.policy("freshness:\n  feeds: {default: 3650d}\n")
    policy_path = next(site.root.glob("policy-*.yaml"))
    assert policy.name
    paths = _feeds(tmp_path)
    runner = CliRunner()
    inventory = tmp_path / "inventory.json"
    done = runner.invoke(
        main,
        [
            "patch",
            "inventory",
            "--root",
            str(_alma_root(tmp_path)),
            "--label",
            "web-01",
            "--key",
            str(key_file),
            "-o",
            str(inventory),
        ],
    )
    assert done.exit_code == 0, done.output
    assert "3 packages on almalinux 9.4, signed" in done.output
    plan_path = tmp_path / "plan.json"
    feeds = ["--feed", str(paths["updateinfo"]), "--feed", str(paths["kev"])]
    done = runner.invoke(
        main,
        [
            "patch",
            "plan",
            "--inventory",
            str(inventory),
            *feeds,
            "--policy",
            str(policy_path),
            "-o",
            str(plan_path),
            "--markdown",
            str(tmp_path / "plan.md"),
        ],
    )
    assert done.exit_code == 0, done.output
    assert "2 advisories, 1 on KEV, 2 packages to fetch" in done.output
    done = runner.invoke(
        main,
        [
            "patch",
            "confirm",
            "--plan",
            str(plan_path),
            "--inventory",
            str(inventory),
            *feeds,
            "--policy",
            str(policy_path),
        ],
    )
    assert done.exit_code == 1 and '"open"' in done.output  # gaps remain: not accepted
    unsigned = tmp_path / "unsigned.json"
    runner.invoke(
        main,
        [
            "patch",
            "inventory",
            "--root",
            str(_alma_root(tmp_path / "x")),
            "--label",
            "web-01",
            "-o",
            str(unsigned),
        ],
    )
    done = runner.invoke(
        main,
        [
            "patch",
            "plan",
            "--inventory",
            str(unsigned),
            *feeds,
            "--policy",
            str(policy_path),
            "-o",
            str(plan_path),
        ],
    )
    assert done.exit_code != 0 and "not signed by a receipt key" in done.output


# --- Authenticode -------------------------------------------------------------------------------


def test_authenticode_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files: dict[str, bytes | str] = {
        "good.msu": b"MSCF good",
        "tampered.msu": b"MSCF bad",
        "plain.msi": b"\xd0\xcf\x11\xe0",
    }
    result = inspect(write(tmp_path / "d", files), plugins=True)
    gaps = [f for f in result.assessment.findings if f.rule.startswith("authenticode.")]
    assert {f.result for f in gaps} == {Result.NOT_ASSESSED}

    tools = FakeTools(monkeypatch)
    binary, digest = _binary(tmp_path / "tools", "osslsigncode")
    roots = tmp_path / "tools" / "roots"
    roots.mkdir()
    (roots / "roots.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n", encoding="ascii"
    )
    signer = "Signer #0:\n\tSubject: /C=US/O=Microsoft Corporation/CN=Microsoft Windows\n"

    def osslsigncode(args: list[str]) -> Completed:
        if args == ["--version"]:
            return Completed(0, "osslsigncode 2.9, using:\n", "")
        path = args[args.index("-in") + 1]
        if path.endswith("good.msu"):
            return Completed(0, signer + "Signature verification: ok\n", "")
        if path.endswith("tampered.msu"):
            return Completed(
                1,
                signer
                + "Calculated message digest : AB\nMessage digest MISMATCH\nSignature verification: failed\n",
                "",
            )
        return Completed(1, "No signature found\n", "")

    tools.handlers["osslsigncode"] = osslsigncode  # type: ignore[assignment]
    sha = hashlib.sha256((roots / "roots.pem").read_bytes()).hexdigest()
    policy = (
        f"plugins:\n  osslsigncode:\n    path: {binary.as_posix()}\n    binarySha256: {digest}\n"
        f"    database: {roots.as_posix()}\n    files: {{roots.pem: {sha}}}\n"
    )
    result = inspect(write(tmp_path / "e", files), policy_yaml=policy, plugins=True)
    failed = {
        (f.rule, f.subject.display)
        for f in findings_of(result).get("authenticode.signature.invalid", [])
        + findings_of(result).get("authenticode.signature.missing", [])
        if f.result is Result.FAIL
    }
    assert failed == {
        ("authenticode.signature.invalid", "tampered.msu"),
        ("authenticode.signature.missing", "plain.msi"),
    }
    assert all("-CAfile" in c for c in tools.commands("osslsigncode")[1:])


def test_inventory_from_a_package_listing(tmp_path: Path) -> None:
    """AlmaLinux 8 and older keep the RPM database in Berkeley DB: the host lists its packages."""
    root = write(
        tmp_path / "el8",
        {
            "etc/os-release": 'ID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="8.10"\n',
            "var/lib/rpm/Packages": b"\x00\x05\x31\x62 berkeley db",
        },
    )
    with pytest.raises(ConfigError, match="rpm -qa --qf") as refused:
        collect(root, "old-01", NOW)
    assert "--package-list" in str(refused.value)
    listing = tmp_path / "packages.txt"
    listing.write_text(
        "bash 0:4.4.20-5.el8 x86_64\nopenssl 1:1.1.1k-12.el8_9 x86_64\n"
        "gpg-pubkey 0:c21ad6ea-5d7f8d5a (none)\n# a comment\n",
        encoding="utf-8",
    )
    inventory = collect(root, "old-01", NOW, listing)
    assert inventory.os.family == "rpm"
    assert [(p.name, p.version) for p in inventory.packages] == [
        ("bash", "4.4.20-5.el8"),
        ("openssl", "1:1.1.1k-12.el8_9"),
    ]
    debian = write(tmp_path / "deb", {"etc/os-release": 'ID=ubuntu\nVERSION_ID="22.04"\n'})
    listing.write_text(
        "libssl3 3.0.2-0ubuntu1.15 amd64 openssl\nnano 6.2-1 amd64 nano\n", encoding="utf-8"
    )
    listed = collect(debian, "dev-03", NOW, listing)
    assert [(p.name, p.source) for p in listed.packages] == [("libssl3", "openssl"), ("nano", None)]
    listing.write_text("only-a-name\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="line 1"):
        collect(debian, "dev-03", NOW, listing)


def _osv(tmp_path: Path, name: str, affected: list[dict[str, object]]) -> Path:
    record = {"id": name, "summary": "x", "modified": "2026-11-05T00:00:00Z", "affected": affected}
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _affected(ecosystem: str, package: str, fixed: str) -> dict[str, object]:
    return {
        "package": {"name": package, "ecosystem": ecosystem},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


def test_plan_matches_rocky_and_prefers_the_standard_archive(tmp_path: Path) -> None:
    rocky = Inventory(
        "r-01",
        NOW,
        OsIdentity("rpm", "rocky", "9.4"),
        (InstalledPackage("bash", "5.1.8-6.el9", "x86_64"),),
    )
    feed = load_feed(
        _osv(tmp_path, "RLSA-2026:1", [_affected("Rocky Linux:9", "bash", "5.1.8-9.el9")])
    )
    assert [g.advisory for g in plan(rocky, [feed], NOW).gaps] == ["RLSA-2026:1"]
    other = load_feed(_osv(tmp_path, "RLSA-2026:2", [_affected("Rocky Linux:8", "bash", "9-9")]))
    assert plan(rocky, [other], NOW).gaps == ()

    ubuntu = Inventory(
        "u-01",
        NOW,
        OsIdentity("deb", "ubuntu", "22.04"),
        (InstalledPackage("nano", "6.2-1", "amd64"), InstalledPackage("vim", "2:8.2-1", "amd64")),
    )
    usn = load_feed(
        _osv(
            tmp_path,
            "USN-9100-1",
            [
                _affected("Ubuntu:Pro:22.04:LTS", "nano", "6.2-1ubuntu0.1+esm1"),
                _affected("Ubuntu:22.04:LTS", "nano", "6.2-1ubuntu0.1"),
                _affected("Ubuntu:Pro:22.04:LTS", "vim", "2:8.2-1ubuntu0.1+esm2"),
            ],
        )
    )
    [gap] = plan(ubuntu, [usn], NOW).gaps
    by_name = {p.name: p for p in gap.packages}
    assert (by_name["nano"].fixed, by_name["nano"].channel) == ("6.2-1ubuntu0.1", "")
    assert by_name["vim"].channel == "ubuntu-pro"  # only published to Pro subscribers
    assert "(Ubuntu Pro)" in markdown(plan(ubuntu, [usn], NOW))


def test_unreadable_feed_is_stale_not_fatal(tmp_path: Path) -> None:
    from airlock.feeds.readers import load_feeds

    bad = tmp_path / "broken.xml.gz"
    bad.write_bytes(b"\x1f\x8b not gzip at all")
    paths = _feeds(tmp_path)
    result = plan(_alma_inventory(), load_feeds([paths["updateinfo"], bad]), NOW)
    assert result.stale_feeds == ["broken.xml.gz"]
    assert len(result.gaps) == 2
