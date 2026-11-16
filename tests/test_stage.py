"""airlock stage: only accepted bundles, re-hashed on copy, laid out for each receiving tool, and
recorded in the ledger. Also airlock patch stage's downgrade protection."""

import gzip
import json
import re
from collections.abc import Callable, Mapping
from datetime import timedelta
from pathlib import Path

import pytest

from airlock.core import chainlog
from airlock.core.model import Verdict
from airlock.pack import pack
from airlock.patch.inventory import InstalledPackage, Inventory, OsIdentity
from airlock.patch.stage import downgrade_check
from airlock.stage import StageError, stage
from airlock.verify import Verified, verify
from tests.data_fixtures import embedding_model
from tests.helpers import NOW, Site, make_site
from tests.models_helpers import make_policy
from tests.software_fixtures import docker_archive, npm_tarball, wheel_bytes, wheel_name, write
from tests.vendor_fixtures import RPMSpec, primary_xml, repomd_xml, rpm_bytes, sha256_hex

LENIENT = "defaults:\n  severity: {high: warn, medium: warn}\n"
LATER = NOW + timedelta(hours=1)


def _delivery(root: Path) -> Path:
    mirror_rpm = rpm_bytes(RPMSpec(name="mirrored"))
    primary = gzip.compress(
        primary_xml({"Packages/mirrored.rpm": ("mirrored", mirror_rpm)}), mtime=0
    )
    files: dict[str, bytes | str] = {
        **embedding_model("models/embedder"),
        f"wheels/{wheel_name()}": wheel_bytes(),
        "npm/tiny-1.0.0.tgz": npm_tarball("tiny", "1.0.0"),
        "repo/repodata/repomd.xml": repomd_xml({"primary": ("repodata/1-primary.xml.gz", primary)}),
        "repo/repodata/1-primary.xml.gz": primary,
        "repo/Packages/mirrored.rpm": mirror_rpm,
        "updates/tool-2.0-1.el9.x86_64.rpm": rpm_bytes(
            RPMSpec(name="tool", version="2.0", release="1.el9")
        ),
        "windows/windows11.0-kb5050001-x64.msu": b"MSCF pretend update",
        "images/app.tar": docker_archive(),
    }
    return write(root, files)


def _accepted(tmp_path: Path, site: Site) -> tuple[Path, Path]:
    request = tmp_path / "request.yaml"
    request.write_text(
        site.request.read_text(encoding="utf-8").split("  contents:")[0]
        + '  contents:\n    - {name: all, paths: ["**"]}\n',
        encoding="utf-8",
    )
    bundle = pack(
        [_delivery(tmp_path / "delivery")],
        tmp_path / "bundle",
        signer=site.pack_key,
        policy=make_policy(tmp_path / "low", LENIENT),
        request_path=request,
        now=NOW,
    ).bundle
    state = tmp_path / "state"
    result = verify(
        bundle, policy=site.policy(LENIENT), now=NOW, state=state, receipt_signer=site.receipt_key
    )
    assert result.assessment.summary.verdict is Verdict.PASSED
    return bundle, state


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return make_site(tmp_path / "site")


def _stage(site: Site, bundle: Path, state: Path, targets: Mapping[str, Path], **extra: object):  # type: ignore[no-untyped-def]
    return stage(
        bundle,
        policy=site.policy(LENIENT),
        state=state,
        targets=targets,
        now=LATER,
        signer=site.receipt_key,
        **extra,  # type: ignore[arg-type]
    ).report


def test_stage_lays_out_every_target(tmp_path: Path, site: Site) -> None:
    bundle, state = _accepted(tmp_path, site)
    out = tmp_path / "high"
    kinds = ("files", "models", "pypi", "npm", "dnf", "oci", "windows")
    report = _stage(site, bundle, state, {k: out / k for k in kinds})
    counts = {t.kind: t.copied for t in report.targets}
    assert counts["files"] == len(list((bundle / "payload").rglob("*.*")))
    assert (out / "models/embedder/config.json").is_file()
    wheel = wheel_name()
    index = (out / "pypi/simple/tinylib/index.html").read_text(encoding="utf-8")
    assert (
        f"../../packages/{wheel}#sha256={sha256_hex((tmp_path / 'delivery/wheels' / wheel).read_bytes())}"
        in index
    )
    packument = json.loads((out / "npm/tiny/package.json").read_text(encoding="utf-8"))
    assert packument["dist-tags"]["latest"] == "1.0.0"
    assert packument["versions"]["1.0.0"]["dist"]["integrity"].startswith("sha512-")
    assert (out / "dnf/repo/repodata/repomd.xml").is_file()  # the mirror keeps its metadata
    assert (out / "dnf/local/Packages/tool-2.0-1.el9.x86_64.rpm").is_file()
    dnf = next(t for t in report.targets if t.kind == "dnf")
    assert any("createrepo_c" in n for n in dnf.notes)
    assert (out / "windows/windows11.0-kb5050001-x64.msu").is_file()
    oci = next(t for t in report.targets if t.kind == "oci")
    assert oci.copied == 1 and "skopeo" in oci.notes[0]
    [event] = [e for e in chainlog.read(state / "ledger.jsonl") if e.type == "stage"]
    assert event.data["manifestDigest"] == report.manifest_digest
    assert event.data["targets"]["pypi"] == {"copied": 1, "present": 0}
    # Staging again copies nothing new: identical files are already present.
    again = _stage(site, bundle, state, {"files": out / "files"})
    assert (again.targets[0].copied, again.targets[0].present) == (0, counts["files"])


def test_stage_refuses_what_was_not_accepted(tmp_path: Path, site: Site) -> None:
    bundle, state = _accepted(tmp_path, site)
    with pytest.raises(StageError, match="not been accepted"):
        _stage(site, bundle, tmp_path / "other-state", {"files": tmp_path / "out"})
    with pytest.raises(Exception, match="unknown stage target"):
        _stage(site, bundle, state, {"harbor": tmp_path / "out"})
    with pytest.raises(Exception, match="give --key"):
        stage(
            bundle,
            policy=site.policy(LENIENT),
            state=state,
            targets={"files": tmp_path / "o"},
            now=LATER,
        )


def test_stage_rehashes_on_copy(tmp_path: Path, site: Site) -> None:
    bundle, state = _accepted(tmp_path, site)

    def tamper(verified: Verified) -> None:
        # Changed after verification, before the copy: the copy itself must catch it.
        verified.files["npm/tiny-1.0.0.tgz"].location.write_bytes(b"swapped")

    out = tmp_path / "out"
    with pytest.raises(StageError, match="changed after it was verified"):
        _stage(site, bundle, state, {"npm": out}, check=tamper)
    assert not list(out.rglob("*.tgz")) and not list(out.rglob("*.airlock-partial"))


def test_stage_never_overwrites(tmp_path: Path, site: Site) -> None:
    bundle, state = _accepted(tmp_path, site)
    out = tmp_path / "out"
    (out / "windows11.0-kb5050001-x64.msu").parent.mkdir(parents=True)
    (out / "windows11.0-kb5050001-x64.msu").write_bytes(b"something else")
    with pytest.raises(StageError, match="already exists with different content"):
        _stage(site, bundle, state, {"windows": out})


def _inventory(tool_version: str) -> Inventory:
    return Inventory(
        "web-01",
        NOW,
        OsIdentity("rpm", "almalinux", "9.4"),
        (InstalledPackage("tool", tool_version, "x86_64"),),
    )


@pytest.mark.parametrize(
    ("installed", "justification", "outcome"),
    [
        ("1.0-1.el9", None, "staged"),
        ("3.0-1.el9", None, "refused"),
        ("3.0-1.el9", "roll back a broken update, CHG-1234", "staged"),
    ],
)
def test_patch_stage_downgrade_protection(
    tmp_path: Path, site: Site, installed: str, justification: str | None, outcome: str
) -> None:
    bundle, state = _accepted(tmp_path, site)
    check: Callable[[Verified], str | None] = downgrade_check(_inventory(installed), justification)
    if outcome == "refused":
        with pytest.raises(
            StageError,
            match=re.escape(
                "refusing to downgrade: tool 3.0-1.el9 installed, bundle has 2.0-1.el9"
            ),
        ):
            _stage(site, bundle, state, {"dnf": tmp_path / "dnf"}, check=check)
        return
    report = _stage(site, bundle, state, {"dnf": tmp_path / "dnf"}, check=check)
    if justification:
        assert report.downgrades_allowed and justification in report.downgrades_allowed
    else:
        assert report.downgrades_allowed is None


def test_stage_cli(tmp_path: Path, site: Site) -> None:
    from click.testing import CliRunner

    from airlock.cli import main
    from airlock.core.signing import save_key

    bundle, state = _accepted(tmp_path, site)
    key = tmp_path / "receipt.key"
    save_key(site.receipt_key, key, tmp_path / "receipt.pub", None)
    site.policy(LENIENT)
    policy = sorted(site.root.glob("policy-*.yaml"))[-1]
    out = tmp_path / "pypi"
    args = ["stage", str(bundle), "--policy", str(policy), "--state", str(state)]
    done = CliRunner().invoke(main, [*args, "--target", f"pypi={out}", "--key", str(key)])
    assert done.exit_code == 0, done.output
    assert "pypi: 1 copied, 0 already present" in done.output
    done = CliRunner().invoke(main, [*args, "--target", "pypi", "--key", str(key)])
    assert done.exit_code != 0 and "KIND=DIRECTORY" in done.output


def _stage_events(state: Path) -> list[dict[str, object]]:
    return [dict(e.data) for e in chainlog.read(state / "ledger.jsonl") if e.type == "stage"]


def test_stage_report_is_kept_and_failures_are_recorded(tmp_path: Path, site: Site) -> None:
    bundle, state = _accepted(tmp_path, site)
    staged = stage(
        bundle,
        policy=site.policy(LENIENT),
        state=state,
        targets={"windows": tmp_path / "ok"},
        now=LATER,
        signer=site.receipt_key,
    )
    assert json.loads(staged.path.read_bytes())["kind"] == "StageReport"
    assert staged.path.parent.parent == state / "stages"
    [event] = _stage_events(state)
    assert event["outcome"] == "staged"

    # Part-way failure: the npm target cannot be completed, after another target was staged.
    blocked = tmp_path / "blocked" / "tiny"
    blocked.parent.mkdir()
    blocked.write_text("a file where a directory is needed", encoding="utf-8")
    with pytest.raises(StageError, match="could not stage"):
        _stage(site, bundle, state, {"files": tmp_path / "files", "npm": tmp_path / "blocked"})
    failed = _stage_events(state)[-1]
    assert failed["outcome"] == "failed"
    assert failed["targets"]["files"]["copied"] > 0 and failed["targets"]["npm"]["copied"] == 0
    reports = sorted((state / "stages").glob("*/stage-report.json"))
    assert json.loads(reports[-1].read_bytes())["failed"].startswith("could not stage")


def test_stage_judges_the_bundle_as_of_its_acceptance(tmp_path: Path, site: Site) -> None:
    """The policy refuses bundles older than 30 days at import. Staging months after an accepted
    import is still staging what was accepted; a leftover partial file is replaced."""
    bundle, state = _accepted(tmp_path, site)
    out = tmp_path / "late"
    out.mkdir()
    (out / "windows11.0-kb5050001-x64.msu.airlock-partial").write_bytes(b"interrupted")
    months_later = NOW + timedelta(days=200)
    staged = stage(
        bundle,
        policy=site.policy(LENIENT),
        state=state,
        targets={"windows": out},
        now=months_later,
        signer=site.receipt_key,
    )
    assert staged.report.staged_at == months_later
    assert (out / "windows11.0-kb5050001-x64.msu").read_bytes() == b"MSCF pretend update"
    assert not list(out.glob("*.airlock-partial"))


def test_stage_cli_exit_codes(tmp_path: Path, site: Site) -> None:
    from click.testing import CliRunner

    from airlock.cli import main
    from airlock.core.signing import save_key

    bundle, state = _accepted(tmp_path, site)
    key = tmp_path / "receipt.key"
    save_key(site.receipt_key, key, tmp_path / "receipt.pub", None)
    site.policy(LENIENT)
    policy = sorted(site.root.glob("policy-*.yaml"))[-1]
    common = ["--policy", str(policy), "--key", str(key), "--target", f"files={tmp_path / 'o'}"]
    never = CliRunner().invoke(
        main, ["stage", str(bundle), "--state", str(tmp_path / "s2"), *common]
    )
    assert never.exit_code == 3 and "refused: this bundle has not been accepted" in never.output
    done = CliRunner().invoke(main, ["stage", str(bundle), "--state", str(state), *common])
    assert done.exit_code == 0 and "report: " in done.output
