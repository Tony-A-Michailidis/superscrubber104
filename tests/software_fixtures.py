"""Tiny, synthetic software artifacts: container images, wheels, npm packages, agent configs."""

import base64
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

FAKE_TOKEN = "ghp_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"  # a made-up token-shaped string

DPKG_STATUS = """\
Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.36-9+deb12u4
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
"""
OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'


def tar_bytes(files: Mapping[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def image_config(diff_ids: list[str], *, user: str = "app", env: list[str] | None = None) -> bytes:
    return json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": user,
                "Env": env or ["PATH=/usr/local/bin:/usr/bin"],
                "Entrypoint": ["/app/run"],
                "ExposedPorts": {"8080/tcp": {}},
                "Labels": {"org.opencontainers.image.source": "https://example.org/app"},
            },
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{d}" for d in diff_ids]},
            "history": [{"created_by": "COPY . /app"}],
        }
    ).encode()


BASE_LAYER = {
    "etc/os-release": OS_RELEASE,
    "var/lib/dpkg/status": DPKG_STATUS,
}


def docker_archive(
    layers: list[Mapping[str, bytes | str]] | None = None,
    *,
    tag: str = "registry.example.org/team/app:1.0",
    user: str = "app",
    env: list[str] | None = None,
    tamper_layer: bool = False,
    drop_layer: bool = False,
) -> bytes:
    """A legacy ``docker save`` archive: <id>/layer.tar plus <config>.json and manifest.json."""
    layer_tars = [tar_bytes(files) for files in (layers or [BASE_LAYER])]
    config = image_config([sha(t) for t in layer_tars], user=user, env=env)
    config_name = f"{sha(config)}.json"
    files: dict[str, bytes | str] = {config_name: config}
    paths = []
    for index, data in enumerate(layer_tars):
        path = f"{index:064x}/layer.tar"
        paths.append(path)
        if drop_layer and index == 0:
            continue
        files[path] = data + (b"\0" * 512 if tamper_layer and index == 0 else b"")
    files["manifest.json"] = json.dumps(
        [{"Config": config_name, "RepoTags": [tag], "Layers": paths}]
    )
    files["repositories"] = json.dumps({tag.rsplit(":", 1)[0]: {tag.rsplit(":", 1)[1]: "x"}})
    return tar_bytes(files)


def oci_blobs(
    layers: list[Mapping[str, bytes | str]] | None = None,
    *,
    tag: str = "registry.example.org/team/app:2.0",
    user: str = "app",
    gzip_layers: bool = True,
) -> dict[str, bytes | str]:
    """The files of an OCI image layout: oci-layout, index.json and blobs/sha256/*."""
    tars = [tar_bytes(files) for files in (layers or [BASE_LAYER])]
    blobs = [gzip.compress(t, mtime=0) if gzip_layers else t for t in tars]
    config = image_config([sha(t) for t in tars], user=user)
    layer_type = "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if gzip_layers else "")
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{sha(config)}",
                "size": len(config),
            },
            "layers": [
                {"mediaType": layer_type, "digest": f"sha256:{sha(b)}", "size": len(b)}
                for b in blobs
            ],
        }
    ).encode()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{sha(manifest)}",
                    "size": len(manifest),
                    "annotations": {"io.containerd.image.name": tag},
                }
            ],
        }
    )
    files: dict[str, bytes | str] = {
        "oci-layout": '{"imageLayoutVersion": "1.0.0"}',
        "index.json": index,
        f"blobs/sha256/{sha(config)}": config,
        f"blobs/sha256/{sha(manifest)}": manifest,
    }
    for blob in blobs:
        files[f"blobs/sha256/{sha(blob)}"] = blob
    return files


# --- Python -------------------------------------------------------------------------------------


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def wheel_bytes(
    name: str = "tinylib",
    version: str = "1.0.0",
    *,
    licence: str | None = "MIT",
    pth: str | None = None,
    tamper: bool = False,
    extra_file: bool = False,
) -> bytes:
    dist = f"{name}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nSummary: test\n"
    if licence:
        metadata += f"License-Expression: {licence}\n"
    files: dict[str, bytes] = {
        f"{name}/__init__.py": b"VALUE = 1\n",
        f"{dist}/METADATA": metadata.encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    if pth is not None:
        files[f"{name}.pth"] = pth.encode()
    record = "".join(f"{path},{_record_hash(data)},{len(data)}\n" for path, data in files.items())
    record += f"{dist}/RECORD,,\n"
    files[f"{dist}/RECORD"] = record.encode()
    if tamper:
        files[f"{name}/__init__.py"] = b"import os; os.system('id')\n"
    if extra_file:
        files[f"{name}/sneaky.py"] = b"print('not in RECORD')\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    return buffer.getvalue()


def wheel_name(name: str = "tinylib", version: str = "1.0.0", tag: str = "py3-none-any") -> str:
    return f"{name}-{version}-{tag}.whl"


# --- npm ----------------------------------------------------------------------------------------


def npm_tarball(
    name: str, version: str, scripts: Mapping[str, str] | None = None, licence: str = "MIT"
) -> bytes:
    manifest = {
        "name": name,
        "version": version,
        "license": licence,
        "scripts": dict(scripts or {}),
    }
    raw = tar_bytes(
        {"package/package.json": json.dumps(manifest), "package/index.js": "module.exports = 1;\n"}
    )
    return gzip.compress(raw, mtime=0)


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def package_lock(entries: Mapping[str, Mapping[str, object]]) -> str:
    packages: dict[str, object] = {"": {"name": "app", "version": "1.0.0"}}
    packages.update(entries)
    return json.dumps(
        {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    )


def write(root: Path, files: Mapping[str, bytes | str]) -> Path:
    for name, data in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
    return root
