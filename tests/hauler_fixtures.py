"""Synthetic Hauler hauls, built to Hauler's documented layout (doc 35 §35.3).

A haul is an OCI image layout in a tar: ``oci-layout``, ``index.json`` and content-addressed
blobs. Each index entry carries ``org.opencontainers.image.ref.name``; images and the signatures
kept beside them carry Hauler's ``kind`` annotation. Charts and files are OCI artifacts with
Helm's and Hauler's media types. No real haul was available, so these follow the docs and the
source's constants, not a sample.
"""

import gzip
import json
from collections.abc import Mapping, Sequence

from tests.model_fixtures import safetensors_bytes
from tests.zarf_fixtures import sha, tar

INSTALL = b"#!/bin/sh\necho 'installing the demo'\n"
CHART = {
    "demo/Chart.yaml": b"apiVersion: v2\nname: demo\nversion: 1.0.0\n",
    "demo/templates/cm.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n",
}


class Layout:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.entries: list[dict[str, object]] = []

    def blob(self, data: bytes) -> dict[str, object]:
        self.blobs[f"blobs/sha256/{sha(data)}"] = data
        return {"digest": f"sha256:{sha(data)}", "size": len(data)}

    def add(
        self,
        reference: str,
        config: tuple[bytes, str],
        layers: Sequence[tuple[bytes, str, Mapping[str, str]]],
        kind: str | None = None,
    ) -> str:
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": config[1], **self.blob(config[0])},
                "layers": [
                    {"mediaType": media, **self.blob(data), "annotations": dict(notes)}
                    for data, media, notes in layers
                ],
            }
        ).encode()
        annotations = {"org.opencontainers.image.ref.name": reference}
        if kind:
            annotations["kind"] = kind
        self.entries.append(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                **self.blob(manifest),
                "annotations": annotations,
            }
        )
        return sha(manifest)

    def members(self) -> dict[str, bytes]:
        index = {"schemaVersion": 2, "manifests": self.entries}
        return {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": json.dumps(index).encode(),
            **self.blobs,
        }


def haul(*, signatures: bool = True) -> dict[str, bytes]:
    """An image (with a model in its layer), a chart, a file, and a signature for the image."""
    layout = Layout()
    layer_tar = tar(
        {
            "models/tiny/model.safetensors": safetensors_bytes({"w": ("F32", (2, 4))}),
            "models/tiny/config.json": b'{"model_type": "bert", "hidden_size": 4}',
        }
    )
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"User": "1000"},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{sha(layer_tar)}"]},
        }
    ).encode()
    image = layout.add(
        "docker.io/example/model-server:2.1",
        (config, "application/vnd.oci.image.config.v1+json"),
        [(gzip.compress(layer_tar, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip", {})],
        kind="dev.hauler/image",
    )
    layout.add(
        "hauler/demo:1.0.0",
        (b'{"name": "demo", "version": "1.0.0"}', "application/vnd.cncf.helm.config.v1+json"),
        [
            (
                gzip.compress(tar(CHART), mtime=0),
                "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                {},
            )
        ],
    )
    layout.add(
        "hauler/install.sh:latest",
        (b"{}", "application/vnd.content.hauler.file.config.v1+json"),
        [
            (
                INSTALL,
                "application/vnd.content.hauler.file.layer.v1",
                {"org.opencontainers.image.title": "install.sh"},
            )
        ],
    )
    if signatures:
        layout.add(
            f"docker.io/example/model-server:sha256-{image}.sig",
            (b'{"architecture": "", "os": ""}', "application/vnd.oci.image.config.v1+json"),
            [
                (
                    b'{"critical": {}}',
                    "application/vnd.dev.cosign.simplesigning.v1+json",
                    {"dev.cosignproject.cosign/signature": "MEUCIQ"},
                )
            ],
            kind="dev.hauler/sigs",
        )
    return layout.members()


def haul_bytes(members: Mapping[str, bytes], fmt: str = "tar") -> bytes:
    data = tar(members)
    if fmt == "gzip":
        return gzip.compress(data, mtime=0)
    if fmt == "zstd":
        from superscrubber104.archive import zstd_module

        return bytes(zstd_module().compress(data))
    return data
