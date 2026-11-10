"""Minimal protobuf wire-format reader.

Walks fields of a message held in a seekable stream without building objects, so a multi-GB
ONNX model can be inspected while skipping its weights. Every length is checked against the
enclosing message and nesting depth is capped, so a malformed file raises ProtobufError rather
than reading out of bounds or recursing without limit.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from io import BytesIO
from typing import IO

VARINT, I64, LEN, I32 = 0, 1, 2, 5
MAX_DEPTH = 64


class ProtobufError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Field:
    number: int
    wire_type: int
    value: int  # the integer for VARINT; the payload length for LEN; 0 otherwise
    start: int  # absolute offset of the payload


class Message:
    """One message: the byte range ``[start, end)`` of ``stream``."""

    def __init__(self, stream: IO[bytes], start: int, end: int, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            raise ProtobufError("messages are nested too deeply")
        self.stream = stream
        self.start = start
        self.end = end
        self.depth = depth

    @classmethod
    def of_bytes(cls, data: bytes) -> "Message":
        return cls(BytesIO(data), 0, len(data))

    @classmethod
    def of_stream(cls, stream: IO[bytes], size: int) -> "Message":
        return cls(stream, 0, size)

    def _varint(self, limit: int) -> int:
        result = shift = 0
        for _ in range(10):
            if self.stream.tell() >= limit:
                raise ProtobufError("truncated varint")
            byte = self.stream.read(1)
            if not byte:
                raise ProtobufError("truncated varint")
            result |= (byte[0] & 0x7F) << shift
            if not byte[0] & 0x80:
                return result
            shift += 7
        raise ProtobufError("varint is too long")

    def fields(self) -> Iterator[Field]:
        """Each field in order. The stream may be moved freely between iterations."""
        position = self.start
        while position < self.end:
            self.stream.seek(position)
            key = self._varint(self.end)
            number, wire_type = key >> 3, key & 7
            if number == 0:
                raise ProtobufError("field number 0")
            if wire_type == VARINT:
                value = self._varint(self.end)
                field = Field(number, wire_type, value, self.stream.tell())
                position = self.stream.tell()
            elif wire_type in (I64, I32):
                width = 8 if wire_type == I64 else 4
                field = Field(number, wire_type, 0, self.stream.tell())
                position = field.start + width
            elif wire_type == LEN:
                length = self._varint(self.end)
                start = self.stream.tell()
                field = Field(number, wire_type, length, start)
                position = start + length
            else:
                raise ProtobufError(f"unsupported wire type {wire_type}")
            if position > self.end:
                raise ProtobufError(f"field {number} runs past the end of its message")
            yield field

    def sub(self, field: Field) -> "Message":
        if field.wire_type != LEN:
            raise ProtobufError(f"field {field.number} is not a message")
        return Message(self.stream, field.start, field.start + field.value, self.depth + 1)

    def read(self, field: Field, limit: int = 1 << 20) -> bytes:
        """The payload of a LEN field, if it is no longer than ``limit``."""
        if field.wire_type != LEN:
            raise ProtobufError(f"field {field.number} has no payload")
        if field.value > limit:
            raise ProtobufError(f"field {field.number} is larger than {limit} bytes")
        self.stream.seek(field.start)
        data = self.stream.read(field.value)
        if len(data) != field.value:
            raise ProtobufError("truncated payload")
        return data

    def text(self, field: Field, limit: int = 1 << 16) -> str:
        return self.read(field, limit).decode("utf-8", "replace")

    def varints(self, field: Field) -> list[int]:
        """A repeated integer field, packed (one LEN field) or not (a single VARINT)."""
        if field.wire_type == VARINT:
            return [field.value]
        packed = Message.of_bytes(self.read(field))
        values = []
        while packed.stream.tell() < packed.end:
            values.append(packed._varint(packed.end))
        return values
