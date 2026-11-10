"""GGUF header parsing and validation (llama.cpp's model format).

Layout: magic ``GGUF``, a version, a tensor count and a key/value count, then the key/values,
then one record per tensor (name, dimensions, type, offset), then the tensor data, aligned.

Everything is read with explicit limits. Large arrays (the tokenizer's vocabulary is often
150 000 strings) are counted, not kept. Tensor sizes are computed for the types whose block
layout is fixed and well known, so that a truncated or padded file is caught; tensors of other
types are reported but not size-checked.
"""

import itertools
import struct
from dataclasses import dataclass, field
from math import prod
from typing import IO

MAGIC = b"GGUF"
DEFAULT_ALIGNMENT = 32
_MAX_STRING = 16 * 1024 * 1024  # chat templates are long; nothing legitimate is this long
_MAX_KEPT_STRING = 1024 * 1024
_MAX_COUNT = 100_000_000
_MAX_DIMS = 8
_KEPT_ARRAY = 64  # arrays up to this length are kept; longer ones are only counted

# value type -> (struct format or None)
_SCALARS = {
    0: "<B",
    1: "<b",
    2: "<H",
    3: "<h",
    4: "<I",
    5: "<i",
    6: "<f",
    7: "<?",
    10: "<Q",
    11: "<q",
    12: "<d",
}
_STRING, _ARRAY = 8, 9

# ggml type -> (name, elements per block, bytes per block); only fixed, well-known layouts
GGML_TYPES = {
    0: ("F32", 1, 4), 1: ("F16", 1, 2), 2: ("Q4_0", 32, 18), 3: ("Q4_1", 32, 20),
    6: ("Q5_0", 32, 22), 7: ("Q5_1", 32, 24), 8: ("Q8_0", 32, 34), 9: ("Q8_1", 32, 36),
    10: ("Q2_K", 256, 84), 11: ("Q3_K", 256, 110), 12: ("Q4_K", 256, 144),
    13: ("Q5_K", 256, 176), 14: ("Q6_K", 256, 210), 15: ("Q8_K", 256, 292),
    20: ("IQ4_NL", 32, 18), 23: ("IQ4_XS", 256, 136), 24: ("I8", 1, 1), 25: ("I16", 1, 2),
    26: ("I32", 1, 4), 27: ("I64", 1, 8), 28: ("F64", 1, 8), 30: ("BF16", 1, 2),
}  # fmt: skip

# general.file_type (llama_ftype) -> the quantisation name people use
FILE_TYPES = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1", 10: "Q2_K",
    11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S",
    17: "Q5_K_M", 18: "Q6_K", 19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S", 22: "IQ3_XS",
    23: "IQ3_XXS", 24: "IQ1_S", 25: "IQ4_NL", 26: "IQ3_S", 27: "IQ3_M", 28: "IQ2_S",
    29: "IQ2_M", 30: "IQ4_XS", 31: "IQ1_M", 32: "BF16", 36: "TQ1_0", 37: "TQ2_0",
    38: "MXFP4_MOE",
}  # fmt: skip


class GGUFError(ValueError):
    pass


@dataclass
class ArrayInfo:
    """A long array: its element type and length only."""

    element_type: int
    count: int


@dataclass
class TensorInfo:
    name: str
    dims: list[int]
    type: int
    offset: int

    @property
    def elements(self) -> int:
        return prod(self.dims)

    @property
    def nbytes(self) -> int | None:
        layout = GGML_TYPES.get(self.type)
        if layout is None:
            return None
        _, block, size = layout
        if self.elements % block:
            raise GGUFError(f"tensor {self.name!r}: {self.elements} elements is not whole blocks")
        return self.elements // block * size


@dataclass
class GGUF:
    version: int
    metadata: dict[str, object] = field(default_factory=dict)
    tensors: list[TensorInfo] = field(default_factory=list)
    data_start: int = 0
    data_bytes: int = 0  # bytes covered by size-checked tensors' extents
    unsized_types: set[int] = field(default_factory=set)

    def get(self, key: str) -> object:
        return self.metadata.get(key)

    def text(self, key: str) -> str | None:
        value = self.metadata.get(key)
        return value if isinstance(value, str) else None

    def number(self, key: str) -> int | None:
        value = self.metadata.get(key)
        return value if type(value) is int else None

    @property
    def architecture(self) -> str | None:
        return self.text("general.architecture")

    def arch(self, suffix: str) -> object:
        return self.metadata.get(f"{self.architecture}.{suffix}")

    @property
    def quantization(self) -> str | None:
        file_type = self.number("general.file_type")
        return FILE_TYPES.get(file_type, f"ftype-{file_type}") if file_type is not None else None

    @property
    def parameters(self) -> int:
        return sum(t.elements for t in self.tensors)

    def type_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for tensor in self.tensors:
            name = (
                GGML_TYPES[tensor.type][0] if tensor.type in GGML_TYPES else f"type-{tensor.type}"
            )
            counts[name] = counts.get(name, 0) + 1
        return dict(sorted(counts.items()))

    def array_length(self, key: str) -> int | None:
        value = self.metadata.get(key)
        if isinstance(value, ArrayInfo):
            return value.count
        if isinstance(value, list):
            return len(value)
        return None


class _Reader:
    def __init__(self, stream: IO[bytes], size: int, version: int = 3) -> None:
        self.stream = stream
        self.size = size
        self.version = version

    def read(self, n: int) -> bytes:
        if self.stream.tell() + n > self.size:
            raise GGUFError("truncated header")
        data = self.stream.read(n)
        if len(data) != n:
            raise GGUFError("truncated header")
        return data

    def unpack(self, fmt: str) -> object:
        value: object = struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]
        return value

    def uint(self, fmt: str) -> int:
        value = self.unpack(fmt)
        if not isinstance(value, int):
            raise GGUFError(f"expected an integer for {fmt}")
        return value

    def count(self) -> int:
        value = self.uint("<I" if self.version == 1 else "<Q")
        if value > _MAX_COUNT:
            raise GGUFError(f"count {value} is unreasonably large")
        return value

    def string(self, keep: int = _MAX_KEPT_STRING) -> str | None:
        length = self.count()
        if length > _MAX_STRING:
            raise GGUFError(f"string of {length} bytes is unreasonably long")
        if length > keep:
            self.stream.seek(self.stream.tell() + length)
            if self.stream.tell() > self.size:
                raise GGUFError("truncated header")
            return None
        return self.read(length).decode("utf-8", "replace")

    def value(self, value_type: int, depth: int = 0) -> object:
        if value_type in _SCALARS:
            return self.unpack(_SCALARS[value_type])
        if value_type == _STRING:
            return self.string()
        if value_type == _ARRAY:
            if depth > 2:
                raise GGUFError("arrays nested too deeply")
            element_type = self.uint("<I")
            count = self.count()
            if count > _KEPT_ARRAY:
                self.skip_values(element_type, count, depth)
                return ArrayInfo(element_type, count)
            return [self.value(element_type, depth + 1) for _ in range(count)]
        raise GGUFError(f"unknown value type {value_type}")

    def skip_values(self, element_type: int, count: int, depth: int) -> None:
        if element_type in _SCALARS:
            width = struct.calcsize(_SCALARS[element_type])
            self.stream.seek(self.stream.tell() + width * count)
            if self.stream.tell() > self.size:
                raise GGUFError("truncated header")
            return
        for _ in range(count):
            if element_type == _STRING:
                self.string(keep=0)
            else:
                self.value(element_type, depth + 1)


def looks_like(head: bytes) -> bool:
    return head[:4] == MAGIC and int.from_bytes(head[4:8], "little") in (1, 2, 3)


def parse(stream: IO[bytes], size: int) -> GGUF:
    """Parse the header and tensor table and check every sized tensor lies within the file."""
    reader = _Reader(stream, size)
    if reader.read(4) != MAGIC:
        raise GGUFError("not a GGUF file")
    version = reader.uint("<I")
    if version not in (1, 2, 3):
        raise GGUFError(f"unsupported GGUF version {version}")
    reader.version = version
    model = GGUF(version)
    tensor_count, kv_count = reader.count(), reader.count()

    for _ in range(kv_count):
        key = reader.string(keep=64 * 1024)
        value_type = reader.uint("<I")
        value = reader.value(value_type)
        if key is None:
            raise GGUFError("metadata key is unreasonably long")
        if key in model.metadata:
            raise GGUFError(f"duplicate metadata key {key!r}")
        model.metadata[key] = value

    names = set()
    for _ in range(tensor_count):
        name = reader.string(keep=64 * 1024)
        if name is None or name in names:
            raise GGUFError(f"invalid or duplicate tensor name {name!r}")
        names.add(name)
        n_dims = reader.uint("<I")
        if n_dims > _MAX_DIMS:
            raise GGUFError(f"tensor {name!r} has {n_dims} dimensions")
        dims = [reader.count() for _ in range(n_dims)]
        tensor_type = reader.uint("<I")
        offset = reader.uint("<Q")
        model.tensors.append(TensorInfo(name, dims, tensor_type, offset))

    alignment = model.number("general.alignment") or DEFAULT_ALIGNMENT
    if alignment <= 0 or alignment & (alignment - 1):
        raise GGUFError(f"general.alignment {alignment} is not a power of two")
    position = stream.tell()
    model.data_start = position + (-position % alignment)

    extents = []
    for tensor in model.tensors:
        if tensor.offset % alignment:
            raise GGUFError(f"tensor {tensor.name!r} is not aligned to {alignment}")
        nbytes = tensor.nbytes
        if nbytes is None:
            model.unsized_types.add(tensor.type)
            continue
        end = model.data_start + tensor.offset + nbytes
        if end > size:
            raise GGUFError(
                f"tensor {tensor.name!r} ends at byte {end}, past the end of the file ({size}); "
                "the file is truncated or its header is wrong"
            )
        extents.append((tensor.offset, tensor.offset + nbytes, tensor.name))
    extents.sort()
    for (_, end, name), (begin, _, following) in itertools.pairwise(extents):
        if begin < end:
            raise GGUFError(f"tensors {name!r} and {following!r} overlap")
    model.data_bytes = extents[-1][1] if extents else 0
    return model
