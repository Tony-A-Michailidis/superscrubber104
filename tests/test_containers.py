"""Container images: docker save archives and OCI layouts."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

from superscrubber104.core.model import ComponentType, Severity, UnitKind, Verdict
from tests.model_fixtures import safetensors_bytes
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import (
    BASE_LAYER,
    FAKE_TOKEN,
    docker_archive,
    oci_blobs,
    tar_bytes,
    write,
)


def _unit(result, root: str):  # type: ignore[no-untyped-def]
    return next(
        u
        for u in result.analysis.units
        if u.kind is UnitKind.CONTAINER_IMAGE and u.root.display == root
    )


def test_docker_archive(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {"images/app.tar": docker_archive()}))
    found = findings_of(result)
    assert "container.layer.digest-mismatch" not in found
    assert "container.image.incomplete" not in found
    assert "container.user.root" not in found
    unit = _unit(result, "images/app.tar")
    assert unit.name == "registry.example.org/team/app:1.0"
    [image] = unit.attributes["images"]
    assert image["user"] == "app"
    assert image["exposedPorts"] == ["8080/tcp"]
    assert image["env"] == ["PATH"]
    [container] = [c for c in result.analysis.components if c.type is ComponentType.CONTAINER]
    assert container.name == "registry.example.org/team/app"
    assert container.version == "1.0"
    assert container.purl.startswith("pkg:oci/app@sha256%3A")
    assert artifact(result, "images/app.tar").metadata["container"]["blobsChecked"] == 2
    # The layers are walked like any archive: the OS package database feeds the SBOM.
    packages = {
        c.name: c.purl for c in result.analysis.components if c.type is ComponentType.LIBRARY
    }
    assert packages == {
        "libc6": "pkg:deb/debian/libc6@2.36-9%2Bdeb12u4?arch=amd64",
        "openssl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64",
    }
    [os_component] = [
        c for c in result.analysis.components if c.type is ComponentType.OPERATING_SYSTEM
    ]
    assert (os_component.name, os_component.version) == ("debian", "12")


def test_root_user_and_credentials_in_env(tmp_path: Path) -> None:
    archive = docker_archive(
        user="", env=["PATH=/usr/bin", f"GITHUB_TOKEN={FAKE_TOKEN}", "DB_PASSWORD=${DB_PASSWORD}"]
    )
    found = findings_of(inspect(write(tmp_path / "d", {"app.tar": archive})))
    assert found["container.user.root"][0].detail["user"] == "(not set)"
    [credential] = found["container.env.credential"]
    assert credential.detail["variables"] == ["GITHUB_TOKEN"]
    assert FAKE_TOKEN not in json.dumps(credential.detail)


def test_tampered_and_incomplete_images(tmp_path: Path) -> None:
    tampered = inspect(write(tmp_path / "t", {"app.tar": docker_archive(tamper_layer=True)}))
    [mismatch] = findings_of(tampered)["container.layer.digest-mismatch"]
    assert mismatch.detail["blobs"][0]["blob"].endswith("/layer.tar")
    assert tampered.assessment.summary.verdict is Verdict.REFUSED

    incomplete = inspect(write(tmp_path / "i", {"app.tar": docker_archive(drop_layer=True)}))
    [missing] = findings_of(incomplete)["container.image.incomplete"]
    assert missing.detail["missing"] == [f"layer: {0:064x}/layer.tar"]


def test_oci_archive_with_a_model_inside(tmp_path: Path) -> None:
    layer: dict[str, bytes | str] = {
        **BASE_LAYER,
        "models/tiny/model.safetensors": safetensors_bytes({"w": ("F32", [4])}),
    }
    blobs = oci_blobs([layer])
    result = inspect(write(tmp_path / "d", {"app-oci.tar": tar_bytes(blobs)}))
    found = findings_of(result)
    assert "container.layer.digest-mismatch" not in found
    unit = _unit(result, "app-oci.tar")
    assert unit.name == "registry.example.org/team/app:2.0"
    assert unit.attributes["images"][0]["manifestDigest"].startswith("sha256:")
    # The model inside the gzip layer is found and forms its own package.
    models = [u for u in result.analysis.units if u.kind is UnitKind.MODEL_PACKAGE]
    assert models and models[0].root.path == "app-oci.tar"


def test_oci_blob_that_does_not_match_its_name(tmp_path: Path) -> None:
    blobs = oci_blobs(gzip_layers=False)
    layer_path = next(
        p
        for p, d in blobs.items()
        if p.startswith("blobs/") and isinstance(d, bytes) and d[257:262] == b"ustar"
    )
    blobs[layer_path] = tar_bytes({"etc/passwd": "root:x:0:0::/root:/bin/sh\n"})
    result = inspect(write(tmp_path / "d", {"app.tar": tar_bytes(blobs)}))
    [mismatch] = findings_of(result)["container.layer.digest-mismatch"]
    assert mismatch.detail["blobs"][0]["blob"] == layer_path
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_oci_layout_directory(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {f"oci/{p}": d for p, d in oci_blobs().items()}))
    assert artifact(result, "oci/index.json").kinds[0] == "container.image.oci-layout"
    unit = _unit(result, "oci")
    assert unit.attributes["images"][0]["os"] == "linux"
    assert "container.image.incomplete" not in findings_of(result)


def _partial_multiplatform(blobs: dict[str, bytes | str], *, keep_local: bool) -> None:
    """Wrap the image in a multi-platform index the way docker save (containerd store) does:
    the whole index, but blobs only for the local platform."""
    index = json.loads(blobs["index.json"])
    [local] = index["manifests"]
    local = {**local, "platform": {"os": "linux", "architecture": "amd64"}}
    local.pop("annotations")
    absent = [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": f"sha256:{digit * 64}",
            "size": 100,
            **extra,
        }
        for digit, extra in (
            ("a", {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}}),
            (
                "b",
                {
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                },
            ),
            ("c", {"platform": {"os": "linux", "architecture": "s390x"}}),
        )
    ]
    nested = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": ([local] if keep_local else []) + absent,
        }
    ).encode()
    digest = hashlib.sha256(nested).hexdigest()
    blobs[f"blobs/sha256/{digest}"] = nested
    blobs["index.json"] = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": f"sha256:{digest}",
                    "size": len(nested),
                    "annotations": {"io.containerd.image.name": "docker.io/library/app:1"},
                }
            ],
        }
    )


def test_multiplatform_index_saved_for_one_platform(tmp_path: Path) -> None:
    blobs = oci_blobs()
    _partial_multiplatform(blobs, keep_local=True)
    result = inspect(write(tmp_path / "d", {"app.tar": tar_bytes(blobs)}))
    found = findings_of(result)
    assert "container.image.incomplete" not in found
    assert "container.layer.digest-mismatch" not in found
    metadata = artifact(result, "app.tar").metadata["container"]
    assert metadata["notDelivered"] == {
        "attestation-manifest": 1,
        "linux/arm64/v8": 1,
        "linux/s390x": 1,
    }
    assert _unit(result, "app.tar").attributes["images"][0]["architecture"] == "amd64"


def test_multiplatform_index_with_no_platform_delivered(tmp_path: Path) -> None:
    blobs = oci_blobs()
    _partial_multiplatform(blobs, keep_local=False)
    found = findings_of(inspect(write(tmp_path / "d", {"app.tar": tar_bytes(blobs)})))
    [missing] = found["container.image.incomplete"]
    assert missing.detail["missing"] == [f"manifest: blobs/sha256/{d * 64}" for d in "abc"]


def test_a_plain_tar_is_not_an_image(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {"backup.tar": tar_bytes({"notes.txt": "hello"})}))
    assert not [u for u in result.analysis.units if u.kind is UnitKind.CONTAINER_IMAGE]
    assert artifact(result, "backup.tar").kinds == ("archive.tar",)


def _tar(dirs: list[str], links: dict[str, str], files: dict[str, int]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in dirs:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for name, target in links.items():
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            archive.addfile(info)
        for name, mode in files.items():
            info = tarfile.TarInfo(name)
            info.mode, info.size = mode, 1
            archive.addfile(info, io.BytesIO(b"x"))
    return buffer.getvalue()


def test_root_filesystem_links_and_setuid(tmp_path: Path) -> None:
    # Base images use absolute links and setuid binaries; inside a rootfs that is normal.
    rootfs = _tar(["bin", "etc", "usr", "lib"], {"bin/sh": "/bin/busybox"}, {"bin/busybox": 0o4755})
    found = findings_of(inspect(write(tmp_path / "d", {"rootfs.tar": rootfs})))
    assert "archive.member.link-escape" not in found
    [setuid] = found["archive.member.setuid"]
    assert setuid.severity is Severity.LOW

    # The same link in an ordinary archive points out of it.
    plain = _tar(["app"], {"app/escape": "/etc/passwd"}, {"app/run": 0o755})
    found = findings_of(inspect(write(tmp_path / "e", {"bundle.tar": plain})))
    assert "archive.member.link-escape" in found
