"""Models that cannot be inspected, and models packaged with an executable.

Compiled and hardware-bound formats (TensorRT engines, TFLite, Core ML, OpenVINO IR, TensorFlow
SavedModel) are recognised and recorded, and a finding says plainly that their content was not
inspected: the reviewer should know which parts of a delivery were taken on trust.

llamafile-style bundles are an executable and a model in one file: they get both treatments.
"""

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject
from superscrubber104.handlers.ai.common import TOOL, claim, name_of

_APE = b"MZqFpD"  # Actually Portable Executable, used by llamafile


def _opaque(ctx: Context, view: ArtifactView, fmt: str, note: str) -> None:
    ctx.recorder.fail(
        "model.format.opaque",
        Subject.of_artifact(view.ref),
        tool=TOOL,
        detail={"format": fmt, "note": note},
        attributes={"format": fmt},
    )


class OpaqueModelHandler:
    name = "opaque-model"
    version = "1"
    kinds = frozenset(
        {
            "model.tensorrt",
            "model.tflite",
            "model.coreml",
            "model.openvino",
            "model.tensorflow.savedmodel",
            "model.llamafile",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        name = name_of(artifact.ref).lower()
        head = artifact.head(512)
        if head.startswith(_APE):
            return Detection("model.llamafile", 70)
        if head[4:8] == b"TFL3":
            return Detection("model.tflite", 100)
        if name.endswith((".engine", ".plan", ".trt")):
            return Detection("model.tensorrt", 60)
        if name.endswith(".mlmodel"):
            return Detection("model.coreml", 60)
        if name.endswith(".xml") and b"<net " in head:
            return Detection("model.openvino", 80)
        if name in ("saved_model.pb", "saved_model.pbtxt"):
            return Detection("model.tensorflow.savedmodel", 80)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        detection = self.detect(artifact)
        assert detection is not None  # noqa: S101 - only called after detect()
        kind = detection.kind
        name = name_of(artifact.ref).lower()
        if kind == "model.llamafile":
            ctx.recorder.fail(
                "model.format.executable",
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                detail={
                    "format": "actually-portable-executable",
                    "note": "the file runs as a program on Windows, Linux and macOS; it is "
                    "handled as an executable as well as a model",
                    "llamafile": name.endswith(".llamafile"),
                },
            )
            return Inspection(
                kind=kind,
                media_type="application/x-executable",
                claims=(claim(artifact, "llamafile", {"format": "llamafile"}, root=artifact.ref),),
            )
        notes = {
            "model.tensorrt": "compiled for one GPU architecture and TensorRT version; the target "
            "must match",
            "model.tflite": "custom operators are not detected",
            "model.coreml": "compiled Core ML model; content is not inspected",
            "model.openvino": "the weights are in the matching .bin file; custom layers are not "
            "detected",
            "model.tensorflow.savedmodel": "custom TensorFlow operators are not detected",
        }
        _opaque(ctx, artifact, kind.removeprefix("model."), notes[kind])
        root = artifact.ref if kind != "model.tensorflow.savedmodel" else None
        fmt = kind.removeprefix("model.")
        return Inspection(
            kind=kind,
            claims=(claim(artifact, "opaque-model", {"format": fmt}, root=root),),
        )
