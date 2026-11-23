"""Keras models: Lambda layers and custom objects.

A Keras ``Lambda`` layer stores Python bytecode that runs when the model is loaded (unless the
loader runs in safe mode, which an attacker cannot rely on being off but a defender cannot rely on
being on). Custom objects name classes from outside Keras, which must be importable at load time.

``.keras`` files are zips with a ``config.json``, which is parsed. Legacy ``.h5`` files keep the
same JSON in an HDF5 attribute; without an HDF5 parser the file is searched for the markers
instead, and the finding says so.
"""

import json
import zipfile

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject
from superscrubber104.handlers.ai.common import TOOL, claim, name_of
from superscrubber104.handlers.ai.weights import shard_facts, weight_role

_HDF5 = b"\x89HDF\r\n\x1a\n"
_KERAS_MODULES = ("keras", "tensorflow", "tf_keras", "tf.keras")
_LAMBDA_MARKERS = (b'"class_name": "Lambda"', b'"class_name":"Lambda"')
_MAX_CONFIG = 64 << 20
_CHUNK = 1 << 20


def _walk(node: object, path: str, lambdas: list[str], custom: list[str]) -> None:
    if isinstance(node, dict):
        cls = node.get("class_name")
        if cls == "Lambda":
            config = node.get("config")
            name = config.get("name") if isinstance(config, dict) else None
            lambdas.append(str(name or path))
        module = node.get("module")
        if (
            isinstance(cls, str)
            and isinstance(module, str)
            and not module.startswith(_KERAS_MODULES)
        ):
            custom.append(f"{module}.{cls}")
        for key, value in node.items():
            _walk(value, f"{path}/{key}", lambdas, custom)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, f"{path}/{index}", lambdas, custom)


def _report(
    ctx: Context, view: ArtifactView, lambdas: list[str], custom: list[str], method: str
) -> None:
    subject = Subject.of_artifact(view.ref)
    if lambdas:
        ctx.recorder.fail(
            "model.keras.lambda-layer",
            subject,
            tool=TOOL,
            detail={"layers": sorted(set(lambdas))[:50], "method": method},
        )
    else:
        ctx.recorder.passed("model.keras.lambda-layer")
    if custom:
        ctx.recorder.fail(
            "model.keras.custom-object",
            subject,
            tool=TOOL,
            detail={"objects": sorted(set(custom))[:50]},
        )
    else:
        ctx.recorder.passed("model.keras.custom-object")


class KerasHandler:
    name = "keras"
    version = "1"
    kinds = frozenset({"model.keras", "model.keras.h5", "model.keras.weights"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        name = name_of(artifact.ref).lower()
        head = artifact.head(8)
        if name.endswith(".keras") and head[:4] == b"PK\x03\x04":
            return Detection("model.keras", 90)
        if head == _HDF5 and name.endswith((".h5", ".hdf5", ".keras")):
            return Detection("model.keras.h5", 70)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        if artifact.head(8) == _HDF5:
            return self._h5(artifact, ctx)
        try:
            with artifact.open() as stream, zipfile.ZipFile(stream) as archive:
                info = archive.getinfo("config.json")
                if info.file_size > _MAX_CONFIG:
                    raise ValueError("config.json is too large")
                config = json.loads(archive.read(info))
                meta = (
                    json.loads(archive.read("metadata.json"))
                    if "metadata.json" in archive.namelist()
                    else {}
                )
        except (KeyError, ValueError, zipfile.BadZipFile, OSError) as exc:
            ctx.recorder.not_assessed(
                ("model.keras.lambda-layer", "model.keras.custom-object"),
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason=f"config.json could not be read: {exc}",
            )
            return Inspection(kind="model.keras")
        lambdas: list[str] = []
        custom: list[str] = []
        _walk(config, "", lambdas, custom)
        _report(ctx, artifact, lambdas, custom, "config.json")
        summary = {
            "format": "keras-v3",
            "className": config.get("class_name") if isinstance(config, dict) else None,
            "kerasVersion": meta.get("keras_version") if isinstance(meta, dict) else None,
            "lambdaLayers": len(lambdas),
        }
        return Inspection(
            kind="model.keras",
            metadata={"keras": summary},
            claims=(claim(artifact, "keras", {"format": "keras", **summary}, root=artifact.ref),),
        )

    def _h5(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        found_config = found_layers = False
        lambdas: list[str] = []
        overlap = max(len(m) for m in _LAMBDA_MARKERS)
        tail = b""
        with artifact.open() as stream:
            while chunk := stream.read(_CHUNK):
                window = tail + chunk
                found_config = found_config or b"model_config" in window
                found_layers = found_layers or b"layer_names" in window
                if any(marker in window for marker in _LAMBDA_MARKERS):
                    lambdas.append("found by byte search")
                    found_config = True
                    break
                tail = window[-overlap:]
        if not found_config and found_layers:
            # Keras save_weights (Transformers' tf_model.h5): layer_names and weights, no model
            # config, so nothing in it can run. Weights of the package in its directory.
            name = name_of(artifact.ref)
            return Inspection(
                kind="model.keras.weights",
                metadata={"keras": {"format": "keras-weights-h5", "modelConfig": False}},
                claims=(
                    claim(
                        artifact,
                        weight_role(name),
                        {"format": "keras-weights-h5", "file": name, **shard_facts(name)},
                    ),
                ),
            )
        if not found_config:  # HDF5 is also a data format: not every .h5 is a model
            return Inspection(kind="unclassified", metadata={"hdf5": {"kerasModel": False}})
        _report(ctx, artifact, lambdas, [], "byte search of the HDF5 file; layer names unavailable")
        summary = {"format": "keras-h5", "lambdaLayers": len(lambdas)}
        return Inspection(
            kind="model.keras.h5",
            metadata={"keras": summary},
            claims=(claim(artifact, "keras", {"format": "keras-h5"}, root=artifact.ref),),
        )
