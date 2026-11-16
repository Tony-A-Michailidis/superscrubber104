"""Package repository mirrors: dnf, apt, PyPI simple, npm storage and Helm, with the chain from
signed metadata to each package, freshness and rollback. Fixtures: ``tests/vendor_fixtures.py``."""

import base64
import gzip
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from airlock.core.model import Result, TrustLevel, UnitKind, Verdict
from airlock.pack import pack
from airlock.verify import verify
from tests.helpers import NOW, Site, make_site
from tests.models_helpers import artifact, findings_of, inspect, make_policy
from tests.software_fixtures import write
from tests.vendor_fixtures import (
    PGPKey,
    RPMSpec,
    deb_bytes,
    packages_index,
    primary_xml,
    release_text,
    repomd_xml,
    rpm_bytes,
    sha256_hex,
)

ED = PGPKey()
OTHER = PGPKey()


def _anchors(tmp: Path, *anchors: tuple[str, PGPKey, str]) -> str:
    tmp.mkdir(parents=True, exist_ok=True)
    lines = ["trust:", "  upstream:"]
    for name, key, scope in anchors:
        data = key.public()
        (tmp / f"{name}.asc").write_bytes(data)
        lines += [
            f"    - name: {name}",
            "      type: gpg",
            f"      file: {(tmp / f'{name}.asc').as_posix()}",
            f'      sha256: "{hashlib.sha256(data).hexdigest()}"',
            f'      scope: ["{scope}"]',
        ]
    return "\n".join(lines) + "\n"


def _mirror(result, root: str):  # type: ignore[no-untyped-def]
    return next(u for u in result.analysis.units if u.id == f"repo-mirror:{root}")


def _failing(result, rule: str) -> list[str]:  # type: ignore[no-untyped-def]
    return sorted(
        f.subject.display for f in findings_of(result).get(rule, []) if f.result is Result.FAIL
    )


# --- dnf ----------------------------------------------------------------------------------------


def _dnf(signer: PGPKey | None = ED, *, tamper_primary: bool = False) -> dict[str, bytes | str]:
    good = rpm_bytes(RPMSpec(name="good"))
    bad = rpm_bytes(RPMSpec(name="bad"))
    primary = gzip.compress(
        primary_xml(
            {
                "Packages/good.rpm": ("good", good),
                "Packages/bad.rpm": ("bad", b"what the index says bad.rpm is"),
                "Packages/absent.rpm": ("absent", b"not shipped"),
            }
        ),
        mtime=0,
    )
    repomd = repomd_xml({"primary": ("repodata/1234-primary.xml.gz", primary)})
    if tamper_primary:  # the same listing, compressed again: not the bytes repomd.xml names
        primary = gzip.compress(gzip.decompress(primary), mtime=1)
    files: dict[str, bytes | str] = {
        "repo/repodata/repomd.xml": repomd,
        "repo/repodata/1234-primary.xml.gz": primary,
        "repo/Packages/good.rpm": good,
        "repo/Packages/bad.rpm": bad,
        "repo/Packages/extra.rpm": rpm_bytes(RPMSpec(name="extra")),
    }
    if signer is not None:
        files["repo/repodata/repomd.xml.asc"] = signer.detached(repomd)
    return files


def test_dnf_chain_from_signed_metadata(tmp_path: Path) -> None:
    policy = _anchors(tmp_path / "k", ("vendor", ED, "repo.dnf"))
    result = inspect(write(tmp_path / "d", _dnf()), policy_yaml=policy)
    unit = _mirror(result, "repo")
    attributes = unit.attributes
    assert attributes["format"] == "dnf"
    assert attributes["signatures"] == {
        "repodata/repomd.xml": {"status": "verified", "anchor": "vendor"}
    }
    assert (attributes["chainedIndexes"], attributes["missing"]) == (1, 1)
    [check] = artifact(result, "repo/Packages/good.rpm").verifications
    assert (check.type, check.level, check.anchor) == (
        "repo-metadata",
        TrustLevel.SIGNATURE,
        "vendor",
    )
    assert (
        artifact(result, "repo/repodata/repomd.xml").verifications[0].level is TrustLevel.SIGNATURE
    )
    assert artifact(result, "repo/repodata/1234-primary.xml.gz").verifications[0].anchor == "vendor"
    assert _failing(result, "repo.content.digest-mismatch") == ["repo/Packages/bad.rpm"]
    assert not artifact(result, "repo/Packages/bad.rpm").verifications
    [missing] = findings_of(result)["repo.content.missing"]
    assert missing.detail["sample"] == ["Packages/absent.rpm"]
    [unlisted] = findings_of(result)["repo.content.unlisted"]
    assert unlisted.detail["files"] == ["Packages/extra.rpm"]
    assert result.assessment.summary.verdict is Verdict.REFUSED  # the mismatch is final


def test_dnf_tampered_index_and_unsigned_metadata(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", _dnf(None, tamper_primary=True)))
    assert _failing(result, "repo.metadata.unsigned") == ["repo/repodata/repomd.xml"]
    assert _failing(result, "repo.metadata.digest-mismatch") == [
        "repo/repodata/1234-primary.xml.gz"
    ]
    # The index is no longer vouched for, so its packages only have the index's word.
    assert _failing(result, "repo.metadata.unlisted") == ["repo/repodata/1234-primary.xml.gz"]
    [check] = artifact(result, "repo/Packages/good.rpm").verifications
    assert check.level is TrustLevel.CHECKSUM


def test_dnf_untrusted_and_invalid_signatures(tmp_path: Path) -> None:
    files = {f"a/{k[5:]}": v for k, v in _dnf(OTHER).items()}
    files |= {f"b/{k[5:]}": v for k, v in _dnf(ED).items()}
    files["b/repodata/repomd.xml.asc"] = ED.detached(b"something else")
    policy = _anchors(tmp_path / "k", ("vendor", ED, "repo.dnf"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    assert _failing(result, "repo.metadata.signature.untrusted") == ["a/repodata/repomd.xml"]
    assert _failing(result, "repo.metadata.signature.invalid") == ["b/repodata/repomd.xml"]
    for root in ("a", "b"):
        [check] = artifact(result, f"{root}/Packages/good.rpm").verifications
        assert check.level is TrustLevel.CHECKSUM


# --- apt ----------------------------------------------------------------------------------------


def _apt(*, date: str, valid_until: str | None = None, key: PGPKey = ED) -> dict[str, bytes | str]:
    hello = deb_bytes()
    plain = packages_index(
        {
            "pool/main/h/hello/hello_2.10-3_amd64.deb": ("hello", "2.10-3", hello),
            "pool/main/g/gone/gone_1.0_amd64.deb": ("gone", "1.0", b"absent"),
        }
    ).encode()
    packed = gzip.compress(plain, mtime=0)
    release = release_text(
        {"main/binary-amd64/Packages": plain, "main/binary-amd64/Packages.gz": packed},
        date=date,
        valid_until=valid_until,
    )
    return {
        "apt/dists/stable/InRelease": key.clearsign(release),
        "apt/dists/stable/main/binary-amd64/Packages": plain,
        "apt/dists/stable/main/binary-amd64/Packages.gz": packed,
        "apt/pool/main/h/hello/hello_2.10-3_amd64.deb": hello,
    }


def test_apt_chain_expiry_and_freshness(tmp_path: Path) -> None:
    files = _apt(date="Sat, 01 Nov 2026 00:00:00 UTC", valid_until="Sun, 08 Nov 2026 00:00:00 UTC")
    policy = _anchors(tmp_path / "k", ("archive", ED, "repo.apt"))
    policy += "freshness:\n  mirrors: {default: 30d, apt: 5d}\n"
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    unit = _mirror(result, "apt")
    assert unit.attributes["snapshots"] == {"apt:Example/stable": "2026-11-01T00:00:00Z"}
    assert unit.attributes["chainedIndexes"] == 2
    [check] = artifact(result, "apt/pool/main/h/hello/hello_2.10-3_amd64.deb").verifications
    assert (check.level, check.anchor) == (TrustLevel.SIGNATURE, "archive")
    assert _failing(result, "repo.metadata.expired") == ["apt/dists/stable/InRelease"]
    [stale] = findings_of(result)["repo.metadata.stale"]
    assert (stale.detail["ageDays"], stale.detail["maxAgeDays"]) == (9, 5)
    [missing] = findings_of(result)["repo.content.missing"]
    assert missing.detail["count"] == 1  # read once, though the index is there twice
    plain = artifact(result, "apt/dists/stable/main/binary-amd64/Packages")
    assert plain.metadata["repoIndex"]["sameAs"] == "Packages.gz"


def test_apt_release_with_detached_signature(tmp_path: Path) -> None:
    files = _apt(date="Sun, 08 Nov 2026 00:00:00 UTC")
    text = release_text(
        {
            "main/binary-amd64/Packages.gz": files["apt/dists/stable/main/binary-amd64/Packages.gz"]  # type: ignore[dict-item]
        },
        date="Sun, 08 Nov 2026 00:00:00 UTC",
    ).encode()
    del files["apt/dists/stable/InRelease"], files["apt/dists/stable/main/binary-amd64/Packages"]
    files["apt/dists/stable/Release"] = text
    files["apt/dists/stable/Release.gpg"] = OTHER.detached(text)
    policy = _anchors(tmp_path / "k", ("archive", ED, "repo.apt"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    assert _failing(result, "repo.metadata.signature.untrusted") == ["apt/dists/stable/Release"]
    [check] = artifact(result, "apt/pool/main/h/hello/hello_2.10-3_amd64.deb").verifications
    assert check.level is TrustLevel.CHECKSUM


# --- PyPI, npm, Helm ----------------------------------------------------------------------------


def test_pypi_simple_index(tmp_path: Path) -> None:
    wheel = b"a wheel"
    page = (
        "<html><body>"
        f'<a href="../../packages/tinylib-1.0-py3-none-any.whl#sha256={sha256_hex(wheel)}">w</a>'
        f'<a href="../../packages/tinylib-1.1.tar.gz#sha256={sha256_hex(b"other")}">s</a>'
        '<a href="https://files.example.org/tinylib-0.9.tar.gz#sha256=00">x</a>'
        "</body></html>"
    )
    files: dict[str, bytes | str] = {
        "pypi/simple/tinylib/index.html": page,
        "pypi/packages/tinylib-1.0-py3-none-any.whl": wheel,
        "pypi/packages/tinylib-1.1.tar.gz": b"not the listed sdist",
    }
    result = inspect(write(tmp_path / "d", files))
    unit = _mirror(result, "pypi")
    assert (unit.attributes["format"], unit.attributes["external"]) == ("pypi", 1)
    assert _failing(result, "repo.content.digest-mismatch") == ["pypi/packages/tinylib-1.1.tar.gz"]
    assert _failing(result, "repo.content.external") == ["repo-mirror:pypi"]
    [check] = artifact(result, "pypi/packages/tinylib-1.0-py3-none-any.whl").verifications
    assert (check.type, check.level) == ("repo-index", TrustLevel.CHECKSUM)


def test_npm_registry_storage(tmp_path: Path) -> None:
    good, bad = b"tarball one", b"tarball two"
    sri = "sha512-" + base64.b64encode(hashlib.sha512(good).digest()).decode()

    def packument(name: str) -> str:
        base = f"http://registry.example.org/{name}/-/{name.split('/')[-1]}"
        return json.dumps(
            {
                "_id": name,
                "name": name,
                "dist-tags": {"latest": "1.1.0"},
                "versions": {
                    "1.0.0": {"dist": {"tarball": f"{base}-1.0.0.tgz", "integrity": sri}},
                    "1.1.0": {"dist": {"tarball": f"{base}-1.1.0.tgz", "shasum": "0" * 40}},
                },
            }
        )

    files: dict[str, bytes | str] = {
        "npm/tiny/package.json": packument("tiny"),
        "npm/tiny/tiny-1.0.0.tgz": good,
        "npm/tiny/tiny-1.1.0.tgz": bad,
        "npm/@acme/thing/package.json": packument("@acme/thing"),
        "npm/@acme/thing/thing-1.0.0.tgz": good,
    }
    result = inspect(write(tmp_path / "d", files))
    unit = _mirror(result, "npm")
    assert unit.attributes["packages"] == 3
    assert unit.attributes["missing"] == 1  # @acme/thing 1.1.0
    assert _failing(result, "repo.content.digest-mismatch") == ["npm/tiny/tiny-1.1.0.tgz"]
    assert artifact(result, "npm/@acme/thing/thing-1.0.0.tgz").verifications


def test_helm_repository_and_provenance(tmp_path: Path) -> None:
    chart = b"a chart archive"
    index = (
        "apiVersion: v1\nentries:\n  web:\n"
        f"  - version: 1.0.0\n    digest: {sha256_hex(chart)}\n    urls: [web-1.0.0.tgz]\n"
        "generated: '2026-11-01T00:00:00Z'\n"
    )
    prov = f"apiVersion: v2\nname: web\nversion: 1.0.0\n...\nfiles:\n  web-1.0.0.tgz: sha256:{sha256_hex(chart)}\n"
    files: dict[str, bytes | str] = {
        "charts/index.yaml": index,
        "charts/web-1.0.0.tgz": chart,
        "charts/web-1.0.0.tgz.prov": ED.clearsign(prov),
    }
    policy = _anchors(tmp_path / "k", ("charts", ED, "chart.helm"))
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    unit = _mirror(result, "charts")
    assert unit.attributes["snapshots"] == {"helm:charts": "2026-11-01T00:00:00Z"}
    levels = {v.level for v in artifact(result, "charts/web-1.0.0.tgz").verifications}
    assert levels == {TrustLevel.SIGNATURE, TrustLevel.CHECKSUM}
    assert "upstream.signature.untrusted" not in findings_of(result)


# --- rollback against the ledger ----------------------------------------------------------------


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return make_site(tmp_path / "site")


def test_rollback_to_an_older_snapshot_is_caught(tmp_path: Path, site: Site) -> None:
    keys = tmp_path / "keys"
    anchors = _anchors(keys, ("archive", ED, "repo.apt"))
    extra = anchors.split("\n", 1)[1] + "freshness:\n  mirrors: {default: 3650d}\n"
    policy = site.policy(extra)
    state = tmp_path / "state"

    request = tmp_path / "request.yaml"
    request.write_text(
        site.request.read_text(encoding="utf-8").split("  contents:")[0]
        + '  contents:\n    - {name: mirror, paths: ["apt/**"]}\n',
        encoding="utf-8",
    )

    def transfer(name: str, date: str, when):  # type: ignore[no-untyped-def]
        files = _apt(date=date)
        del files["apt/dists/stable/main/binary-amd64/Packages"]  # keep the mirror complete
        source = write(tmp_path / f"src-{name}", files)
        bundle = pack(
            [source],
            tmp_path / name,
            signer=site.pack_key,
            policy=make_policy(tmp_path / f"policy-{name}", anchors),
            request_path=request,
            now=when,
        ).bundle
        return verify(bundle, policy=policy, now=when, state=state, receipt_signer=site.receipt_key)

    first = transfer("new", "Sun, 08 Nov 2026 00:00:00 UTC", NOW)
    assert first.assessment.summary.verdict is Verdict.PASSED, findings_of(first)
    assert first.receipt is not None
    assert first.receipt.snapshots == {"apt:Example/stable": "2026-11-08T00:00:00Z"}

    later = NOW + timedelta(hours=2)
    second = transfer("old", "Sun, 01 Nov 2026 00:00:00 UTC", later)
    [rollback] = [f for f in second.assessment.findings if f.rule == "repo.metadata.rollback"]
    assert rollback.result is Result.FAIL
    assert rollback.detail["accepted"] == "2026-11-08T00:00:00Z"
    assert second.assessment.summary.verdict is not Verdict.PASSED
    assert [u for u in second.analysis.units if u.kind is UnitKind.REPO_MIRROR]


def test_mirror_inside_an_archive_is_not_assessed(tmp_path: Path) -> None:
    import io
    import tarfile

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, data in _dnf(None).items():
            raw = data if isinstance(data, bytes) else data.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    result = inspect(write(tmp_path / "d", {"mirror.tar": out.getvalue()}))
    gaps = {
        f.subject.display: f.not_assessed_reason or ""
        for f in result.assessment.findings
        if f.rule == "repo.metadata.digest-mismatch" and f.result is Result.NOT_ASSESSED
    }
    assert "deliver the mirror as a directory" in gaps["mirror.tar!/repo/repodata/repomd.xml"]
    assert not [u for u in result.analysis.units if u.kind is UnitKind.REPO_MIRROR]


def test_a_mirror_inside_a_mirror_keeps_its_own_packages(tmp_path: Path) -> None:
    """Packages of an inner repository are not the outer repository's unlisted content."""
    files = dict(_dnf(None))
    files |= {f"repo/extras/{k[5:]}": v for k, v in _dnf(None).items()}
    result = inspect(write(tmp_path / "d", files))
    unlisted = {
        f.subject.display: f.detail["files"] for f in findings_of(result)["repo.content.unlisted"]
    }
    assert unlisted == {
        "repo-mirror:repo": ["Packages/extra.rpm"],
        "repo-mirror:repo/extras": ["Packages/extra.rpm"],
    }


def test_metadata_that_does_not_parse(tmp_path: Path) -> None:
    files = dict(_dnf(None))
    files["repo/repodata/repomd.xml"] = b"<repomd><data type='primary'>"
    files["apt/dists/stable/InRelease"] = "Origin: Example\nthis was never clear-signed\n"
    result = inspect(write(tmp_path / "d", files))
    assert _failing(result, "repo.metadata.malformed") == [
        "apt/dists/stable/InRelease",
        "repo/repodata/repomd.xml",
    ]
    # Without metadata that reads, the index is on its own, and that is said.
    assert _failing(result, "repo.metadata.unlisted") == ["repo/repodata/1234-primary.xml.gz"]
