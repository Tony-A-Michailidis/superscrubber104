"""Synthetic fixtures for datasets, knowledge bases, notebooks, documents and binaries.

Everything is built from its format's published layout, in memory, with no third-party library:
a Parquet footer in Thrift compact encoding, a FAISS flat index, a Chroma database made with the
standard library's sqlite3, Office files as zips, PDFs as text.
"""

import io
import json
import sqlite3
import struct
import zipfile
import zlib
from collections.abc import Mapping, Sequence

from tests.model_fixtures import safetensors_bytes

# --- Parquet ------------------------------------------------------------------------------------


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _zigzag(n: int) -> bytes:
    return _varint((n << 1) ^ (n >> 63))


class _Struct:
    """Thrift compact-protocol struct writer (only the types a Parquet footer needs)."""

    def __init__(self) -> None:
        self.out = bytearray()
        self.last = 0

    def _header(self, field: int, kind: int) -> None:
        delta = field - self.last
        if 0 < delta <= 15:
            self.out.append((delta << 4) | kind)
        else:
            self.out.append(kind)
            self.out += _zigzag(field)
        self.last = field

    def i32(self, field: int, value: int) -> "_Struct":
        self._header(field, 5)
        self.out += _zigzag(value)
        return self

    def i64(self, field: int, value: int) -> "_Struct":
        self._header(field, 6)
        self.out += _zigzag(value)
        return self

    def string(self, field: int, value: str) -> "_Struct":
        self._header(field, 8)
        data = value.encode()
        self.out += _varint(len(data)) + data
        return self

    def struct(self, field: int, value: "_Struct") -> "_Struct":
        self._header(field, 12)
        self.out += value.bytes()
        return self

    def structs(self, field: int, values: Sequence["_Struct"]) -> "_Struct":
        self._header(field, 9)
        size = len(values)
        self.out.append((min(size, 15) << 4) | 12)
        if size >= 15:
            self.out += _varint(size)
        for value in values:
            self.out += value.bytes()
        return self

    def bytes(self) -> bytes:
        return bytes(self.out) + b"\x00"


def parquet_bytes(
    columns: Sequence[str] = ("text", "label"),
    rows: int = 3,
    *,
    footer_rows: int | None = None,
    chunk_past_end: bool = False,
    truncate: bool = False,
) -> bytes:
    data = b"\x15" * 64  # stands in for column pages
    chunks = [
        _Struct()
        .i64(2, 4)
        .struct(
            3,
            _Struct().i64(7, 32 if not chunk_past_end else 10_000).i64(9, 4 + i * 32),
        )
        for i, _ in enumerate(columns)
    ]
    schema = [_Struct().string(4, "schema").i32(5, len(columns))]
    schema += [_Struct().i32(1, 6).string(4, name) for name in columns]
    footer = (
        _Struct()
        .i32(1, 2)
        .structs(2, schema)
        .i64(3, rows if footer_rows is None else footer_rows)
        .structs(4, [_Struct().structs(1, chunks).i64(2, 64).i64(3, rows)])
        .structs(5, [_Struct().string(1, "huggingface").string(2, "{}")])
        .string(6, "parquet-cpp-arrow version 15.0.0")
        .bytes()
    )
    whole = b"PAR1" + data + footer + struct.pack("<I", len(footer)) + b"PAR1"
    return whole[: len(whole) // 2] if truncate else whole


# --- FAISS --------------------------------------------------------------------------------------


def faiss_flat(dimension: int = 8, vectors: int = 3, *, truncate: bool = False) -> bytes:
    header = b"IxF2" + struct.pack("<iqqqBi", dimension, vectors, 1 << 20, 1 << 20, 1, 1)
    floats = struct.pack(f"<{dimension * vectors}f", *([0.5] * (dimension * vectors)))
    data = header + struct.pack("<Q", dimension * vectors) + floats
    return data[: len(data) - 8] if truncate else data


# --- Chroma -------------------------------------------------------------------------------------


def chroma_sqlite(
    documents: Mapping[str, str], *, model: str | None = "all-MiniLM-L6-v2", dimension: int = 8
) -> bytes:
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT, dimension INTEGER,
                                  database_id TEXT, configuration_json_str TEXT);
        CREATE TABLE embeddings (id INTEGER PRIMARY KEY, segment_id TEXT, embedding_id TEXT);
        CREATE TABLE embedding_metadata (id INTEGER, key TEXT, string_value TEXT,
                                         int_value INTEGER, float_value REAL, bool_value INTEGER);
        CREATE TABLE migrations (dir TEXT, version INTEGER, filename TEXT);
        """
    )
    config: dict[str, object] = {"hnsw": {"space": "cosine"}}
    if model:
        config["embedding_function"] = {
            "type": "known",
            "name": "sentence_transformer",
            "config": {"model_name": model},
        }
    con.execute(
        "INSERT INTO collections VALUES ('c1', 'docs', ?, 'db', ?)", (dimension, json.dumps(config))
    )
    for index, (doc_id, text) in enumerate(documents.items(), start=1):
        con.execute("INSERT INTO embeddings VALUES (?, 's1', ?)", (index, doc_id))
        con.execute(
            "INSERT INTO embedding_metadata VALUES (?, 'chroma:document', ?, NULL, NULL, NULL)",
            (index, text),
        )
    con.execute("INSERT INTO migrations VALUES ('embeddings', 1, '00001.sql')")
    con.commit()
    data = con.serialize()
    con.close()
    return data


# --- embedding model ----------------------------------------------------------------------------


def embedding_model(prefix: str, dimension: int = 8) -> dict[str, bytes | str]:
    """A tiny sentence-transformers package whose embedding dimension is ``dimension``."""
    modules = [
        {"idx": 0, "name": "0", "path": "", "type": "sentence_transformers.models.Transformer"},
        {
            "idx": 1,
            "name": "1",
            "path": "1_Pooling",
            "type": "sentence_transformers.models.Pooling",
        },
    ]
    return {
        f"{prefix}/config.json": json.dumps(
            {
                "architectures": ["BertModel"],
                "model_type": "bert",
                "hidden_size": dimension,
                "vocab_size": 16,
            }
        ),
        f"{prefix}/model.safetensors": safetensors_bytes(
            {"embeddings.word_embeddings.weight": ("F32", [16, dimension])}
        ),
        f"{prefix}/vocab.txt": "\n".join(f"w{i}" for i in range(16)) + "\n",
        f"{prefix}/modules.json": json.dumps(modules),
        f"{prefix}/1_Pooling/config.json": json.dumps(
            {"word_embedding_dimension": dimension, "pooling_mode_mean_tokens": True}
        ),
        f"{prefix}/README.md": "---\nlicense: apache-2.0\nlibrary_name: sentence-transformers\n---\n",
    }


# --- notebooks ----------------------------------------------------------------------------------


def notebook(cells: Sequence[tuple[str, str, bool]]) -> str:
    """Cells as (type, source, has_output)."""
    return json.dumps(
        {
            "nbformat": 4,
            "nbformat_minor": 5,
            "metadata": {
                "kernelspec": {"name": "python3", "language": "python"},
                "language_info": {"name": "python"},
            },
            "cells": [
                {
                    "cell_type": kind,
                    "source": source,
                    "metadata": {},
                    **(
                        {
                            "outputs": [{"output_type": "stream", "name": "stdout", "text": "42\n"}]
                            if output
                            else [],
                            "execution_count": 1,
                        }
                        if kind == "code"
                        else {}
                    ),
                }
                for kind, source, output in cells
            ],
        }
    )


# --- documents ----------------------------------------------------------------------------------


def office_zip(files: Mapping[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        if "word/document.xml" not in files:
            archive.writestr("word/document.xml", "<w:document/>")
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


REMOTE_TEMPLATE_RELS = (
    '<?xml version="1.0"?><Relationships>'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/attachedTemplate" Target="https://templates.example.org/t.dotm" '
    'TargetMode="External"/></Relationships>'
)


def pdf_bytes(body: bytes, *, object_stream: bytes | None = None) -> bytes:
    parts = [b"%PDF-1.7\n", b"1 0 obj\n<< /Type /Catalog " + body + b" >>\nendobj\n"]
    if object_stream is not None:
        packed = zlib.compress(object_stream)
        parts.append(
            b"2 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
            + str(len(packed)).encode()
            + b" >>\nstream\n"
            + packed
            + b"\nendstream\nendobj\n"
        )
    parts.append(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n")
    return b"".join(parts)


# --- executables --------------------------------------------------------------------------------


def elf_bytes() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8  # 64-bit, little-endian
    return ident + struct.pack("<HH", 3, 62) + b"\0" * 100  # shared object, x86-64


def pe_bytes(*, signed: bool = True) -> bytes:
    dos = bytearray(b"MZ" + b"\0" * 62)
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)  # PE32+
    struct.pack_into("<H", optional, 68, 3)  # console
    if signed:
        struct.pack_into("<II", optional, 112 + 4 * 8, 0x4000, 0x1200)  # security directory
    return bytes(dos) + coff + bytes(optional)
