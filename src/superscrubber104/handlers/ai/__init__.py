"""Handlers for AI artifacts: weights, code-capable model formats and model package files."""

from superscrubber104.core.interfaces import Handler
from superscrubber104.handlers.ai.classic import ClassicModelHandler
from superscrubber104.handlers.ai.keras import KerasHandler
from superscrubber104.handlers.ai.ollama import OllamaManifestHandler
from superscrubber104.handlers.ai.onnx import ONNXHandler
from superscrubber104.handlers.ai.opaque import OpaqueModelHandler
from superscrubber104.handlers.ai.package_files import PackageFileHandler
from superscrubber104.handlers.ai.pickles import NumpyHandler, PickleHandler, TorchZipHandler
from superscrubber104.handlers.ai.signature import ModelSignatureHandler
from superscrubber104.handlers.ai.weights import GGUFHandler, SafetensorsHandler


def ai_handlers() -> tuple[Handler, ...]:
    return (
        SafetensorsHandler(),
        GGUFHandler(),
        PickleHandler(),
        TorchZipHandler(),
        NumpyHandler(),
        KerasHandler(),
        ONNXHandler(),
        OpaqueModelHandler(),
        OllamaManifestHandler(),
        ClassicModelHandler(),
        ModelSignatureHandler(),
        PackageFileHandler(),
    )
