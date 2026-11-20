"""safetensors header parsing and validation.

Layout: an 8-byte little-endian header length N, N bytes of JSON, then the tensor data. The
header maps tensor names to dtype, shape and ``[begin, end)`` offsets into the data.

Validation follows the reference implementation's rules and adds the ones that matter for an
superscrubber104: offsets must cover the data region exactly, with no holes, overlaps or trailing
bytes (anything uncovered is data no loader reads, which is where something can hide), and duplicate
keys in the header are rejected (two parsers could disagree about which one wins).
"""

import json
from dataclasses import dataclass, field
from math import prod
from typing import IO

MAX_HEADER = 100 * 1024 * 1024

DTYPE_SIZES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1, "F8_E8M0": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
    "I32": 4, "U32": 4, "F32": 4,
    "I64": 8, "U64": 8, "F64": 8, "C64": 8,
}  # fmt: skip


class SafetensorsError(ValueError):
    pass


@dataclass
class Tensor:
    dtype: str
    shape: list[int]
    begin: int
    end: int

    @property
    def elements(self) -> int:
        return prod(self.shape)


@dataclass
class Header:
    header_bytes: int
    tensors: dict[str, Tensor] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    unknown_dtypes: set[str] = field(default_factory=set)

    @property
    def data_bytes(self) -> int:
        return max((t.end for t in self.tensors.values()), default=0)

    @property
    def parameters(self) -> int:
        return sum(t.elements for t in self.tensors.values())

    def dtype_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for tensor in self.tensors.values():
            counts[tensor.dtype] = counts.get(tensor.dtype, 0) + 1
        return dict(sorted(counts.items()))


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SafetensorsError(f"duplicate key {key!r} in header")
        result[key] = value
    return result


def looks_like(head: bytes, size: int) -> bool:
    if len(head) < 10:
        return False
    length = int.from_bytes(head[:8], "little")
    return 2 <= length <= min(MAX_HEADER, size - 8) and head[8:9] == b"{"


def parse(stream: IO[bytes], size: int) -> Header:
    """Parse and validate. Raises SafetensorsError describing the first problem found."""
    prefix = stream.read(8)
    if len(prefix) != 8:
        raise SafetensorsError("file is shorter than the 8-byte header length")
    length = int.from_bytes(prefix, "little")
    if length > MAX_HEADER:
        raise SafetensorsError(f"header length {length} exceeds {MAX_HEADER}")
    if 8 + length > size:
        raise SafetensorsError("header runs past the end of the file")
    raw = stream.read(length)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafetensorsError(f"header is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SafetensorsError("header is not a JSON object")

    header = Header(header_bytes=length)
    metadata = document.pop("__metadata__", None)
    if metadata is not None:
        if not isinstance(metadata, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()
        ):
            raise SafetensorsError("__metadata__ must map strings to strings")
        header.metadata = metadata

    for name, info in document.items():
        if not isinstance(info, dict):
            raise SafetensorsError(f"tensor {name!r} is not an object")
        dtype, shape, offsets = info.get("dtype"), info.get("shape"), info.get("data_offsets")
        if set(info) - {"dtype", "shape", "data_offsets"}:
            raise SafetensorsError(f"tensor {name!r} has unexpected fields")
        if not isinstance(dtype, str):
            raise SafetensorsError(f"tensor {name!r} has no dtype")
        if not isinstance(shape, list) or not all(type(d) is int and d >= 0 for d in shape):
            raise SafetensorsError(f"tensor {name!r} has an invalid shape")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(type(o) is int and o >= 0 for o in offsets)
            or offsets[0] > offsets[1]
        ):
            raise SafetensorsError(f"tensor {name!r} has invalid data_offsets")
        tensor = Tensor(dtype, shape, offsets[0], offsets[1])
        width = DTYPE_SIZES.get(dtype)
        if width is None:
            header.unknown_dtypes.add(dtype)
        elif tensor.end - tensor.begin != tensor.elements * width:
            raise SafetensorsError(
                f"tensor {name!r}: {tensor.end - tensor.begin} bytes for "
                f"{tensor.elements} x {dtype} elements"
            )
        header.tensors[name] = tensor

    position = 0
    for name, tensor in sorted(header.tensors.items(), key=lambda item: item[1].begin):
        if tensor.begin != position:
            problem = "overlaps the previous tensor" if tensor.begin < position else "leaves a gap"
            raise SafetensorsError(f"tensor {name!r} {problem} at byte {position}")
        position = tensor.end
    data_size = size - 8 - length
    if position != data_size:
        relation = "is shorter than" if data_size < position else "has bytes beyond"
        raise SafetensorsError(
            f"the data region ({data_size} bytes) {relation} what the header describes "
            f"({position} bytes)"
        )
    return header
