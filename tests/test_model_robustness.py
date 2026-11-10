"""Hostile and damaged input must produce findings, never handler crashes."""

import random
from pathlib import Path

import pytest

from tests.model_fixtures import (
    keras_zip,
    npy_object_array,
    obfuscated_pickle,
    onnx_bytes,
    os_system_pickle,
    safetensors_bytes,
    tiny_gguf,
    torch_zip,
    write,
)
from tests.models_helpers import findings_of, inspect

SAMPLES = {
    "w.safetensors": safetensors_bytes({"a": ("F32", [4, 4]), "b": ("F16", [8])}),
    "m.gguf": tiny_gguf(),
    "p.pkl": os_system_pickle(),
    "o.pkl": obfuscated_pickle(),
    "model.pt": torch_zip(),
    "a.npy": npy_object_array(os_system_pickle()),
    "k.keras": keras_zip(lambda_layer=True),
    "m.onnx": onnx_bytes(custom_domain="x.y", external=[("w.bin", 0, 4)]),
    "tokenizer_config.json": b'{"chat_template": "{{ x }}", "auto_map": {"AutoTokenizer": ["a.B", null]}}',
    "tokenizer.model": b"\x0a\x05\x0a\x01a\x15\x00\x00\x80\x3f" * 4,
    "config.json": b'{"model_type": "llama", "vocab_size": 8, "auto_map": {"AutoModel": "x--y.Z"}}',
    "model.safetensors.index.json": b'{"weight_map": {"a": "w.safetensors"}, "metadata": {"total_size": 1}}',
    "README.md": b"---\nlicense: mit\ntags: [a, b]\n---\n# card\n",
}


def _cuts(data: bytes, rng: random.Random) -> list[bytes]:
    points = sorted(
        {
            1,
            2,
            4,
            8,
            9,
            16,
            24,
            len(data) // 2,
            len(data) - 1,
            *rng.sample(range(len(data)), min(8, len(data))),
        }
    )
    flipped = bytearray(data)
    for _ in range(8):
        index = rng.randrange(len(flipped))
        flipped[index] ^= 1 << rng.randrange(8)
    return [data[:p] for p in points if 0 < p < len(data)] + [bytes(flipped)]


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_damaged_files_never_crash_a_handler(tmp_path: Path, name: str) -> None:
    rng = random.Random(name)
    for index, variant in enumerate(_cuts(SAMPLES[name], rng)):
        root = write(tmp_path / f"{index}", {name: variant})
        result = inspect(root)
        errors = findings_of(result).get("inventory.handler.error", [])
        assert not errors, (name, index, [e.detail for e in errors])
