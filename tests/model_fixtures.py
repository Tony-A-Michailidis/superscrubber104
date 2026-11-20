"""Tiny, synthetic model files and packages for tests.

Malicious pickles are written as raw opcode bytes and never loaded. Nothing here downloads
anything or imports an ML framework.
"""

import hashlib
import io
import json
import struct
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from superscrubber104.formats.gguf import GGML_TYPES

COMMIT = "0123456789abcdef0123456789abcdef01234567"
TEMPLATE = (
    "{% for message in messages %}<|{{ message['role'] }}|>\n{{ message['content'] }}"
    "{% endfor %}{% if add_generation_prompt %}<|assistant|>\n{% endif %}"
)
APACHE = "                                 Apache License\n                           Version 2.0, January 2004\n"
LLAMA = "LLAMA 3.1 COMMUNITY LICENSE AGREEMENT\nLlama 3.1 Version Release Date: July 23, 2024\n"

_DTYPE_SIZE = {"F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4, "U8": 1}


# --- safetensors --------------------------------------------------------------------------------


def safetensors_bytes(
    tensors: Mapping[str, tuple[str, Sequence[int]]],
    metadata: Mapping[str, str] | None = None,
) -> bytes:
    header: dict[str, object] = {}
    offset = 0
    for name, (dtype, shape) in tensors.items():
        size = _DTYPE_SIZE[dtype]
        for d in shape:
            size *= d
        header[name] = {
            "dtype": dtype,
            "shape": list(shape),
            "data_offsets": [offset, offset + size],
        }
        offset += size
    if metadata:
        header["__metadata__"] = dict(metadata)
    raw = json.dumps(header).encode()
    raw += b" " * (-len(raw) % 8)
    return struct.pack("<Q", len(raw)) + raw + bytes(offset)


# --- GGUF ---------------------------------------------------------------------------------------


def _gguf_string(value: str) -> bytes:
    data = value.encode()
    return struct.pack("<Q", len(data)) + data


def _gguf_value(value: object) -> bytes:
    if isinstance(value, bool):
        return struct.pack("<I?", 7, value)
    if isinstance(value, int):
        return struct.pack("<IQ", 10, value) if value > 2**31 else struct.pack("<II", 4, value)
    if isinstance(value, float):
        return struct.pack("<If", 6, value)
    if isinstance(value, str):
        return struct.pack("<I", 8) + _gguf_string(value)
    if isinstance(value, list):
        if all(isinstance(v, str) for v in value):
            return struct.pack("<IIQ", 9, 8, len(value)) + b"".join(_gguf_string(v) for v in value)
        return struct.pack("<IIQ", 9, 5, len(value)) + b"".join(struct.pack("<i", v) for v in value)
    raise TypeError(value)


def gguf_bytes(
    metadata: Mapping[str, object],
    tensors: Sequence[tuple[str, Sequence[int], int]] = (),
    *,
    alignment: int = 32,
    truncate: int = 0,
) -> bytes:
    """A GGUF v3 file. ``tensors`` are (name, dims, ggml type); data is zeros."""
    out = b"GGUF" + struct.pack("<IQQ", 3, len(tensors), len(metadata))
    for key, value in metadata.items():
        out += _gguf_string(key) + _gguf_value(value)
    offset = 0
    sizes = []
    for name, dims, ggml_type in tensors:
        _, block, size = GGML_TYPES[ggml_type]
        elements = 1
        for d in dims:
            elements *= d
        nbytes = elements // block * size
        out += _gguf_string(name) + struct.pack("<I", len(dims))
        out += b"".join(struct.pack("<Q", d) for d in dims) + struct.pack("<IQ", ggml_type, offset)
        sizes.append(nbytes)
        offset += nbytes + (-nbytes % alignment)
    out += bytes(-len(out) % alignment)
    out += bytes(offset)
    return out[: len(out) - truncate] if truncate else out


def tiny_gguf(**overrides: object) -> bytes:
    metadata: dict[str, object] = {
        "general.architecture": "llama",
        "general.name": "Tiny Chat",
        "general.file_type": 1,
        "general.license": "apache-2.0",
        "llama.block_count": 2,
        "llama.embedding_length": 32,
        "llama.context_length": 2048,
        "tokenizer.ggml.model": "gpt2",
        "tokenizer.ggml.tokens": [f"t{i}" for i in range(16)],
        "tokenizer.chat_template": TEMPLATE,
    }
    metadata.update(overrides)
    tensors = [
        ("token_embd.weight", [32, 16], 1),
        ("blk.0.attn_q.weight", [32, 32], 1),
        ("blk.1.attn_q.weight", [32, 32], 1),
    ]
    return gguf_bytes(metadata, tensors)


# --- pickles (raw opcodes; never loaded) --------------------------------------------------------


def os_system_pickle() -> bytes:
    """protocol 2: GLOBAL os.system, then REDUCE with ('echo pwned',)."""
    return b"\x80\x02cos\nsystem\nq\x00X\x0a\x00\x00\x00echo pwnedq\x01\x85q\x02Rq\x03."


def obfuscated_pickle() -> bytes:
    """protocol 4: the module and name reach STACK_GLOBAL only through the memo."""
    return (
        b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94"  # push, memoize, push, memoize
        b"00"  # pop both
        b"h\x00h\x01\x93"  # BINGET 0, BINGET 1, STACK_GLOBAL
        b"\x8c\x02id\x85R."
    )


def torch_pickle(extra_global: tuple[str, str] | None = None) -> bytes:
    """What a PyTorch state dict's data.pkl imports, plus optionally one more global."""
    out = b"\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01"
    out += b"ctorch._utils\n_rebuild_tensor_v2\nq\x02)Rq\x03"
    out += b"ctorch\nFloatStorage\nq\x04"
    if extra_global:
        module, name = extra_global
        out += f"c{module}\n{name}\n".encode() + b"q\x05)R"
    return out + b"."


def torch_zip(pickle_bytes: bytes | None = None, *, torchscript: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", pickle_bytes or torch_pickle())
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/data/0", bytes(64))
        if torchscript:
            archive.writestr(
                "archive/code/__torch__/model.py", "def forward(self, x):\n  return x\n"
            )
            archive.writestr("archive/constants.pkl", b"\x80\x02).")
    return buffer.getvalue()


def npy_object_array(pickle_bytes: bytes) -> bytes:
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header += b" " * (-(10 + len(header) + 1) % 64) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + pickle_bytes


def npy_float_array() -> bytes:
    header = b"{'descr': '<f4', 'fortran_order': False, 'shape': (4,), }"
    header += b" " * (-(10 + len(header) + 1) % 64) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + bytes(16)


# --- Keras and ONNX -----------------------------------------------------------------------------


def keras_zip(*, lambda_layer: bool = False, custom: bool = False) -> bytes:
    layers: list[dict[str, object]] = [
        {"module": "keras.layers", "class_name": "Dense", "config": {"name": "dense", "units": 4}},
    ]
    if lambda_layer:
        layers.append(
            {
                "module": "keras.layers",
                "class_name": "Lambda",
                "config": {
                    "name": "sneaky",
                    "function": {"class_name": "__lambda__", "config": {"code": "4wEAAAAA"}},
                },
            }
        )
    if custom:
        layers.append(
            {
                "module": "my_company.layers",
                "class_name": "SecretSauce",
                "config": {"name": "sauce"},
            }
        )
    config = {"module": "keras", "class_name": "Sequential", "config": {"layers": layers}}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("config.json", json.dumps(config))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.5.0"}))
        archive.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + bytes(32))
    return buffer.getvalue()


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(number: int, payload: bytes | str | int) -> bytes:
    if isinstance(payload, int):
        return _varint(number << 3) + _varint(payload)
    data = payload.encode() if isinstance(payload, str) else payload
    return _varint(number << 3 | 2) + _varint(len(data)) + data


def onnx_bytes(
    *,
    custom_domain: str | None = None,
    external: Sequence[tuple[str, int, int]] = (),
    contrib: bool = False,
) -> bytes:
    """A ModelProto. ``external`` holds (location, offset, length) for external tensors."""
    nodes = [_field(1, _field(4, "Relu"))]
    if custom_domain:
        nodes.append(_field(1, _field(4, "SecretOp") + _field(7, custom_domain)))
    if contrib:
        nodes.append(_field(1, _field(4, "FusedMatMul") + _field(7, "com.microsoft")))
    initializers = []
    for index, (location, offset, length) in enumerate(external):
        entries = b"".join(
            _field(13, _field(1, key) + _field(2, value))
            for key, value in (
                ("location", location),
                ("offset", str(offset)),
                ("length", str(length)),
            )
        )
        initializers.append(
            _field(
                5, _field(8, f"w{index}") + _field(1, 4) + _field(2, 1) + entries + _field(14, 1)
            )
        )
    inline = _field(5, _field(8, "inline") + _field(1, 4) + _field(2, 1) + _field(9, bytes(16)))
    graph = b"".join(nodes) + inline + b"".join(initializers) + _field(2, "main")
    return (
        _field(1, 8)
        + _field(2, "test-exporter")
        + _field(3, "1.0")
        + _field(8, _field(1, "") + _field(2, 17))
        + _field(7, graph)
    )


# --- packages -----------------------------------------------------------------------------------


def write(root: Path, files: Mapping[str, bytes | str]) -> Path:
    for name, data in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
    return root


def hf_package(
    root: Path,
    *,
    sharded: bool = True,
    vocab_size: int = 32,
    tokenizer_tokens: int = 32,
    licence: str | None = APACHE,
    card_licence: str | None = "apache-2.0",
    download_records: bool = True,
    template: str = TEMPLATE,
    auto_map: Mapping[str, str] | None = None,
    name: str = "example-org/tiny-chat",
) -> Path:
    """A tiny Llama-style package in Hugging Face layout."""
    hidden = 8
    shard1 = {
        "model.embed_tokens.weight": ("F16", [vocab_size, hidden]),
        "model.layers.0.self_attn.q_proj.weight": ("F16", [hidden, hidden]),
    }
    shard2 = {
        "model.layers.1.self_attn.q_proj.weight": ("F16", [hidden, hidden]),
        "model.norm.weight": ("F16", [hidden]),
        "lm_head.weight": ("F16", [vocab_size, hidden]),
    }
    config: dict[str, object] = {
        "architectures": ["LlamaForCausalLM"],
        "model_type": "llama",
        "vocab_size": vocab_size,
        "hidden_size": hidden,
        "num_hidden_layers": 2,
        "max_position_embeddings": 2048,
        "torch_dtype": "float16",
        "_name_or_path": name,
    }
    if auto_map:
        config["auto_map"] = dict(auto_map)
    files: dict[str, bytes | str] = {
        "config.json": json.dumps(config),
        "generation_config.json": json.dumps({"temperature": 0.7, "top_p": 0.9}),
        "tokenizer.json": json.dumps(
            {
                "model": {
                    "type": "BPE",
                    "vocab": {f"t{i}": i for i in range(tokenizer_tokens - 2)},
                },
                "added_tokens": [{"id": tokenizer_tokens - 2}, {"id": tokenizer_tokens - 1}],
            }
        ),
        "tokenizer_config.json": json.dumps(
            {"tokenizer_class": "LlamaTokenizer", "chat_template": template}
        ),
    }
    if sharded:
        a = safetensors_bytes(shard1, {"format": "pt"})
        b = safetensors_bytes(shard2, {"format": "pt"})
        files["model-00001-of-00002.safetensors"] = a
        files["model-00002-of-00002.safetensors"] = b
        weight_map = {t: "model-00001-of-00002.safetensors" for t in shard1}
        weight_map |= {t: "model-00002-of-00002.safetensors" for t in shard2}
        total = (
            len(a)
            - 8
            - int.from_bytes(a[:8], "little")
            + len(b)
            - 8
            - int.from_bytes(b[:8], "little")
        )
        files["model.safetensors.index.json"] = json.dumps(
            {"metadata": {"total_size": total}, "weight_map": weight_map}
        )
    else:
        files["model.safetensors"] = safetensors_bytes({**shard1, **shard2})
    if licence is not None:
        files["LICENSE"] = licence
    if card_licence is not None:
        files["README.md"] = (
            f"---\nlicense: {card_licence}\npipeline_tag: text-generation\nlanguage: [en]\n---\n"
            "# Tiny chat\n\n## Intended use\n\nTesting superscrubber104.\n\n## Limitations\n\nNone useful.\n"
        )
    write(root, files)
    if download_records:
        for file in sorted(files):
            if file.endswith(".safetensors") or file == "config.json":
                content = (root / file).read_bytes()
                etag = (
                    hashlib.sha256(content).hexdigest()
                    if file.endswith(".safetensors")
                    else hashlib.sha1(
                        b"blob %d\0" % len(content) + content, usedforsecurity=False
                    ).hexdigest()
                )
                write(
                    root,
                    {
                        f".cache/huggingface/download/{file}.metadata": f"{COMMIT}\n{etag}\n1731240000.0\n"
                    },
                )
    return root


def adapter_package(root: Path, base: str = "example-org/tiny-chat") -> Path:
    return write(
        root,
        {
            "adapter_config.json": json.dumps(
                {
                    "peft_type": "LORA",
                    "base_model_name_or_path": base,
                    "r": 8,
                    "lora_alpha": 16,
                    "target_modules": ["q_proj"],
                }
            ),
            "adapter_model.safetensors": safetensors_bytes(
                {"base_model.model.model.layers.0.self_attn.q_proj.lora_A.weight": ("F32", [8, 8])}
            ),
            "README.md": "---\nlicense: mit\nbase_model: example-org/tiny-chat\n---\n# Adapter\n",
        },
    )


def ollama_store(root: Path, *, tamper: bool = False, drop: str | None = None) -> Path:
    """An Ollama model store with one model, library/tiny:latest."""
    blobs: dict[str, bytes | str] = {
        "application/vnd.ollama.image.model": tiny_gguf(),
        "application/vnd.ollama.image.template": "{{ .System }}{{ .Prompt }}",
        "application/vnd.ollama.image.license": LLAMA,
        "application/vnd.ollama.image.params": json.dumps({"stop": ["<|end|>"]}),
    }
    config = json.dumps({"model_format": "gguf", "model_family": "llama"})
    layers = []
    files: dict[str, bytes | str] = {}
    for media_type, content in blobs.items():
        data = content.encode() if isinstance(content, str) else content
        digest = hashlib.sha256(data).hexdigest()
        layers.append({"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(data)})
        if drop != media_type:
            files[f"blobs/sha256-{digest}"] = data + (
                b"x" if tamper and "template" in media_type else b""
            )
    config_digest = hashlib.sha256(config.encode()).hexdigest()
    files[f"blobs/sha256-{config_digest}"] = config
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": f"sha256:{config_digest}",
            "size": len(config),
        },
        "layers": layers,
    }
    files["manifests/registry.ollama.ai/library/tiny/latest"] = json.dumps(manifest)
    return write(root, files)
