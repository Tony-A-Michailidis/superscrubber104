"""Handlers for AI artifacts: weights, code-capable model formats and model package files."""

from airlock.core.interfaces import Handler
from airlock.handlers.ai.keras import KerasHandler
from airlock.handlers.ai.ollama import OllamaManifestHandler
from airlock.handlers.ai.onnx import ONNXHandler
from airlock.handlers.ai.opaque import OpaqueModelHandler
from airlock.handlers.ai.package_files import PackageFileHandler
from airlock.handlers.ai.pickles import NumpyHandler, PickleHandler, TorchZipHandler
from airlock.handlers.ai.weights import GGUFHandler, SafetensorsHandler


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
        PackageFileHandler(),
    )
