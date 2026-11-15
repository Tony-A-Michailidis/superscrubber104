"""Multi-volume bundles, delta bundles and hard-linked payloads."""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from airlock import bundle as layout
from airlock.cli import main
from airlock.core.model import Result, Verdict
from airlock.pack import pack
from airlock.verify import verify
from airlock.volumes import check_volume, load_index
from tests.helpers import NOW, Site, make_site
from tests.models_helpers import make_policy
from tests.software_fixtures import write

MIB = 1 << 20
BIG = bytes(range(256)) * (10 * 1024)  # 2.5 MiB: larger than a 1 MiB volume


def _delivery(root: Path, **extra: bytes | str) -> Path:
    files: dict[str, bytes | str] = {
        "app/main.py": "print('hello')\n",
        "models/blob.bin": BIG,
        "docs/README.md": "# docs\n",
        "vendor/notes.txt": "small\n",
    }
    files.update(extra)
    return write(root, files)


def _pack(site: Site, source: Path, out: Path, **options: object):  # type: ignore[no-untyped-def]
    return pack(
        [source],
        out,
        signer=site.pack_key,
        policy=make_policy(out.parent / f"policy-{out.name}"),
        request_path=site.request,
        now=NOW,
        **options,  # type: ignore[arg-type]
    )


def _failed(result) -> dict[str, list[str]]:  # type: ignore[no-untyped-def]
    out: dict[str, list[str]] = {}
    for f in result.assessment.findings:
        if f.result is Result.FAIL:
            out.setdefault(f.rule, []).append(f.subject.display)
    return out


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return make_site(tmp_path / "site")


def test_multi_volume_round_trip(tmp_path: Path, site: Site) -> None:
    packed = _pack(site, _delivery(tmp_path / "d"), tmp_path / "bundle", volume_size=MIB)
    bundle = packed.bundle
    assert not (bundle / layout.PAYLOAD).exists()
    index = load_index((bundle / layout.VOLUMES).read_bytes())
    assert len(index.volumes) == 3  # 2.5 MiB fills volume 1's remainder, volume 2 and part of 3
    split = [p for v in index.volumes for p in v.pieces if p.path == "models/blob.bin"]
    assert len(split) == 3 and sum(p.size for p in split) == len(BIG)
    for volume in index.volumes:
        label, problems = check_volume(bundle / "volumes" / volume.name)
        assert label.number == volume.number and problems == []

    result = verify(bundle, policy=site.policy(), now=NOW)
    assert result.assessment.summary.verdict is Verdict.PASSED, _failed(result)

    # Each volume on its own medium, outside the bundle directory.
    media = tmp_path / "media"
    shutil.move(str(bundle / "volumes"), media)
    result = verify(bundle, policy=site.policy(), now=NOW, volume_dirs=[media / "0001", media])
    assert result.assessment.summary.verdict is Verdict.PASSED, _failed(result)


def test_damaged_missing_and_extra_volume_content(tmp_path: Path, site: Site) -> None:
    bundle = _pack(site, _delivery(tmp_path / "d"), tmp_path / "bundle", volume_size=MIB).bundle
    piece = sorted((bundle / "volumes" / "0002" / "parts").iterdir())[0]
    data = bytearray(piece.read_bytes())
    data[100] ^= 0xFF
    piece.write_bytes(bytes(data))
    (bundle / "volumes" / "0003" / "payload" / "extra.txt").write_text("slipped in\n")
    _, problems = check_volume(bundle / "volumes" / "0002")
    assert problems == [
        {"piece": piece.relative_to(bundle / "volumes" / "0002").as_posix(), "problem": "differs"}
    ]

    result = verify(bundle, policy=site.policy(), now=NOW)
    failed = _failed(result)
    assert failed["integrity.hash.mismatch"] == ["models/blob.bin"]
    assert failed["integrity.entry.unexpected"] == ["extra.txt"]
    mismatch = next(
        f
        for f in result.assessment.findings
        if f.rule == "integrity.hash.mismatch" and f.result is Result.FAIL
    )
    assert mismatch.detail["damagedPieces"][0]["volume"] == 2
    assert result.assessment.summary.verdict is Verdict.REFUSED

    shutil.rmtree(bundle / "volumes" / "0003")
    failed = _failed(verify(bundle, policy=site.policy(), now=NOW))
    assert "models/blob.bin" in failed["integrity.entry.missing"]


def test_volume_index_is_signed(tmp_path: Path, site: Site) -> None:
    bundle = _pack(site, _delivery(tmp_path / "d"), tmp_path / "bundle", volume_size=MIB).bundle
    index = json.loads((bundle / layout.VOLUMES).read_bytes())
    index["volumeSize"] = 2 * MIB
    (bundle / layout.VOLUMES).write_text(json.dumps(index))
    result = verify(bundle, policy=site.policy(), now=NOW)
    assert "integrity.statement.subject-mismatch" in _failed(result)
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_delta_bundle(tmp_path: Path, site: Site) -> None:
    state = tmp_path / "state"
    base = _pack(site, _delivery(tmp_path / "d1"), tmp_path / "base").bundle
    assert (
        verify(
            base, policy=site.policy(), now=NOW, state=state, receipt_signer=site.receipt_key
        ).assessment.summary.verdict
        is Verdict.PASSED
    )

    delta_source = _delivery(
        tmp_path / "d2", **{"app/main.py": "print('hello, v2')\n", "app/new.py": "x = 1\n"}
    )
    delta = _pack(site, delta_source, tmp_path / "delta", delta_from=base).bundle
    manifest = json.loads((delta / layout.MANIFEST).read_bytes())
    carried = sorted(e["path"] for e in manifest["entries"] if e.get("carried"))
    assert carried == ["docs/README.md", "models/blob.bin", "vendor/notes.txt"]
    assert (
        manifest["base"]
        == "sha256:"
        + __import__("hashlib").sha256((base / layout.MANIFEST).read_bytes()).hexdigest()
    )
    assert not (delta / "payload" / "models" / "blob.bin").exists()
    assert (delta / "payload" / "app" / "new.py").is_file()

    later = NOW.replace(hour=13)
    result = verify(
        delta,
        policy=site.policy(),
        now=later,
        state=state,
        bases=[base],
        receipt_signer=site.receipt_key,
    )
    assert result.assessment.summary.verdict is Verdict.PASSED, _failed(result)

    # Without the base, carried files cannot be checked: said so, not silently passed.
    result = verify(delta, policy=site.policy(), now=later)
    gaps = [
        f
        for f in result.assessment.findings
        if f.result is Result.NOT_ASSESSED and f.rule == "integrity.hash.mismatch"
    ]
    assert len(gaps) == 3

    # A base whose content changed after it was accepted cannot supply carried files.
    (base / "payload" / "models" / "blob.bin").write_bytes(b"swapped")
    result = verify(delta, policy=site.policy(), now=later, bases=[base])
    assert _failed(result)["integrity.hash.mismatch"] == ["models/blob.bin"]
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_delta_on_an_unaccepted_base(tmp_path: Path, site: Site) -> None:
    base = _pack(site, _delivery(tmp_path / "d1"), tmp_path / "base").bundle
    delta = _pack(
        site,
        _delivery(tmp_path / "d2", **{"app/new.py": "x = 1\n"}),
        tmp_path / "delta",
        delta_from=base,
    ).bundle
    result = verify(
        delta, policy=site.policy(), now=NOW, state=tmp_path / "fresh-state", bases=[base]
    )
    assert "delta.base.unknown" in _failed(result)


def test_linked_payload_and_cli(tmp_path: Path, site: Site) -> None:
    source = _delivery(tmp_path / "d")
    bundle = _pack(site, source, tmp_path / "bundle", link=True).bundle
    linked = bundle / "payload" / "models" / "blob.bin"
    assert linked.read_bytes() == BIG
    assert (
        verify(bundle, policy=site.policy(), now=NOW).assessment.summary.verdict is Verdict.PASSED
    )

    volumes = _pack(site, source, tmp_path / "vb", volume_size=MIB).bundle
    result = CliRunner().invoke(main, ["volume", "check", str(volumes / "volumes" / "0001")])
    assert result.exit_code == 0 and "volume 1 of 3" in result.output and "intact" in result.output
