"""Static reader for the Parquet footer: schema, row counts, writer and key/value metadata.

The footer is a Thrift compact-protocol ``FileMetaData`` struct at the end of the file. This
reader decodes it generically (field id -> value) with bounds on size, depth and element counts,
then picks out what an inventory needs. It also checks that every column chunk lies inside the
file, which catches truncated downloads and copies. No column data is read.
"""

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

FOOTER_LIMIT = 64 << 20
_MAX_DEPTH = 16
_MAX_ITEMS = 5_000_000


class ParquetError(ValueError):
    pass


class _Compact:
    """Thrift compact protocol, decoded into plain values: structs become {field id: value}."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.items = 0

    def _byte(self) -> int:
        if self.pos >= len(self.data):
            raise ParquetError("footer ends inside a value")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def _varint(self) -> int:
        shift = result = 0
        while True:
            byte = self._byte()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 70:
                raise ParquetError("varint too long")

    def _zigzag(self) -> int:
        n = self._varint()
        return (n >> 1) ^ -(n & 1)

    def _bytes(self) -> bytes:
        length = self._varint()
        if length > len(self.data) - self.pos:
            raise ParquetError("string runs past the footer")
        value = self.data[self.pos : self.pos + length]
        self.pos += length
        return value

    def _count(self, n: int) -> None:
        self.items += n
        if self.items > _MAX_ITEMS:
            raise ParquetError("footer has more elements than airlock will decode")

    def value(self, kind: int, depth: int) -> object:
        if depth > _MAX_DEPTH:
            raise ParquetError("footer nests too deeply")
        if kind in (1, 2):
            return kind == 1
        if kind == 3:
            return struct.unpack("b", bytes([self._byte()]))[0]
        if kind in (4, 5, 6):
            return self._zigzag()
        if kind == 7:
            if self.pos + 8 > len(self.data):
                raise ParquetError("footer ends inside a double")
            self.pos += 8
            return None  # no floats in an inventory
        if kind == 8:
            return self._bytes()
        if kind in (9, 10):
            header = self._byte()
            size, element = header >> 4, header & 0x0F
            if size == 15:
                size = self._varint()
            self._count(size)
            if element in (1, 2):  # booleans in a list are one byte each
                return [self._byte() == 1 for _ in range(size)]
            return [self.value(element, depth + 1) for _ in range(size)]
        if kind == 11:
            size = self._varint()
            self._count(size)
            if not size:
                return {}
            types = self._byte()
            return {
                self._key(self.value(types >> 4, depth + 1)): self.value(types & 0x0F, depth + 1)
                for _ in range(size)
            }
        if kind == 12:
            return self.struct(depth + 1)
        raise ParquetError(f"unknown compact type {kind}")

    @staticmethod
    def _key(value: object) -> object:
        return value if isinstance(value, int | str | bytes | bool) else repr(value)

    def struct(self, depth: int = 0) -> dict[int, object]:
        fields: dict[int, object] = {}
        last = 0
        while True:
            header = self._byte()
            if header == 0:
                return fields
            delta, kind = header >> 4, header & 0x0F
            field_id = last + delta if delta else self._zigzag()
            if kind in (1, 2):
                fields[field_id] = kind == 1
            else:
                fields[field_id] = self.value(kind, depth)
            last = field_id


@dataclass(frozen=True, slots=True)
class ParquetInfo:
    version: int | None
    rows: int | None
    columns: tuple[str, ...]
    row_groups: int
    created_by: str | None
    metadata_keys: tuple[str, ...]
    problems: tuple[str, ...] = field(default=())


def _text(value: object) -> str | None:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else None


def read_parquet(stream: BinaryIO, size: int) -> ParquetInfo:
    if size < 12:
        raise ParquetError("too small to be a Parquet file")
    stream.seek(size - 8)
    tail = stream.read(8)
    if tail[4:] != b"PAR1":
        raise ParquetError("no PAR1 marker at the end: the file is truncated or not Parquet")
    (length,) = struct.unpack("<I", tail[:4])
    if length > min(FOOTER_LIMIT, size - 12):
        raise ParquetError("footer length points outside the file")
    footer_start = size - 8 - length
    stream.seek(footer_start)
    meta = _Compact(stream.read(length)).struct()

    schema = meta.get(2) if isinstance(meta.get(2), list) else []
    assert isinstance(schema, list)  # noqa: S101
    columns = [
        name
        for element in schema[1:]
        if isinstance(element, dict)
        and not element.get(5)  # leaves only: groups have children
        and (name := _text(element.get(4)))
    ]
    groups = meta.get(4) if isinstance(meta.get(4), list) else []
    assert isinstance(groups, list)  # noqa: S101
    problems: list[str] = []
    total = 0
    for group in groups:
        if not isinstance(group, dict):
            continue
        rows = group.get(3)
        total += rows if isinstance(rows, int) else 0
        chunks = group.get(1) if isinstance(group.get(1), list) else []
        assert isinstance(chunks, list)  # noqa: S101
        for chunk in chunks:
            if not isinstance(chunk, dict):
                continue
            if chunk.get(1):
                problems.append("a column chunk is stored in another file")
            column = chunk.get(3)
            if isinstance(column, dict):
                # A chunk starts at its dictionary page when it has one (field 11), else at its
                # first data page (field 9); total_compressed_size (field 7) covers both.
                data_page, dictionary_page = column.get(9), column.get(11)
                offset = (
                    min(data_page, dictionary_page)
                    if isinstance(data_page, int)
                    and isinstance(dictionary_page, int)
                    and dictionary_page > 0
                    else data_page
                )
                compressed = column.get(7)
                if (
                    isinstance(offset, int)
                    and isinstance(compressed, int)
                    and (offset < 0 or offset + compressed > footer_start)
                ):
                    problems.append("a column chunk lies outside the data region")
    num_rows = meta.get(3) if isinstance(meta.get(3), int) else None
    if num_rows is not None and groups and total != num_rows:
        problems.append(f"row groups hold {total} rows, the footer says {num_rows}")
    pairs = meta.get(5) if isinstance(meta.get(5), list) else []
    assert isinstance(pairs, list)  # noqa: S101
    keys = tuple(k for p in pairs if isinstance(p, dict) and (k := _text(p.get(1))))
    version = meta.get(1)
    return ParquetInfo(
        version=version if isinstance(version, int) else None,
        rows=num_rows if isinstance(num_rows, int) else None,
        columns=tuple(columns),
        row_groups=len(groups),
        created_by=_text(meta.get(6)),
        metadata_keys=keys,
        problems=tuple(dict.fromkeys(problems)),
    )
