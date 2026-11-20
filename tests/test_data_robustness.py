"""Damaged datasets, knowledge bases, notebooks, documents, executables, runtime profiles and
evaluation sets produce findings, never handler crashes."""

import json
import random
from pathlib import Path

import pytest

from superscrubber104.core.model import Result
from tests.data_fixtures import (
    chroma_sqlite,
    elf_bytes,
    faiss_flat,
    notebook,
    office_zip,
    parquet_bytes,
    pdf_bytes,
    pe_bytes,
)
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import write
from tests.test_eval import EVALSET
from tests.test_runtime import PROFILE

MLMODEL = (
    b"flavors:\n  python_function:\n    loader_module: mlflow.sklearn\n    model_path: model.pkl\n"
)
SAMPLES: dict[str, tuple[str, bytes]] = {
    "parquet": ("d/a.parquet", parquet_bytes(rows=3)),
    "faiss": ("kb/index.faiss", faiss_flat()),
    "chroma": ("kb/chroma/chroma.sqlite3", chroma_sqlite({"a": "hello"})),
    "notebook": (
        "nb/a.ipynb",
        notebook(
            [("code", "!pip install x\nimport os", True), ("markdown", "# t", False)]
        ).encode(),
    ),
    "docm": ("docs/a.docm", office_zip({"word/vbaProject.bin": b"\0" * 16})),
    "docx": (
        "docs/a.docx",
        office_zip({"word/document.xml": "<w:document><w:t>hi</w:t></w:document>"}),
    ),
    "pdf": (
        "docs/a.pdf",
        pdf_bytes(
            b"/OpenAction << /S /JavaScript >>", object_stream=b"1 0 obj << /S /JavaScript >>"
        ),
    ),
    "elf": ("bin/a.elf", elf_bytes()),
    "pe": ("bin/a.exe", pe_bytes()),
    "runtime-profile": ("runtime/chat.runtime.yaml", PROFILE.encode()),
    "eval-set": ("eval/smoke.yaml", EVALSET.replace("METHOD", "exact").encode()),
    "mlmodel": ("model/MLmodel", MLMODEL),
    "dataset-info": (
        "d/dataset_info.json",
        json.dumps({"features": {"text": {"dtype": "string"}}, "splits": {"train": {}}}).encode(),
    ),
    "dataset-card": (
        "d/README.md",
        b"---\nlicense: mit\ndataset_info:\n  features: []\n---\n# card\n",
    ),
    "docstore": (
        "kb/docstore.json",
        json.dumps({"docstore/data": {"1": {"__data__": {}}}}).encode(),
    ),
    "dockerfile": ("app/Dockerfile", b"FROM python:3.12\nRUN pip install x\n"),
    "env": ("app/.env", b"HF_HUB_OFFLINE=1\nTRANSFORMERS_OFFLINE=1\n"),
}


def _variants(data: bytes, rng: random.Random) -> list[bytes]:
    points = sorted({1, 4, 16, 64, 257, 512, len(data) // 3, len(data) // 2, len(data) - 1})
    out = [data[:p] for p in points if 0 < p < len(data)]
    for flips in (1, 12, 40, 40):
        damaged = bytearray(data)
        for _ in range(flips):
            index = rng.randrange(len(damaged))
            damaged[index] = rng.choice((0, 0xFF, damaged[index] ^ (1 << rng.randrange(8))))
        out.append(bytes(damaged))
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:200]):  # text: break its structure
        text = data.decode("utf-8", "replace")
        out += [text.replace(":", "").encode(), text.replace('"', "").encode(), b"[]", b"null"]
        out += [text.replace("a", "\x00").encode(), text[: len(text) // 2].encode() + b"{["]
    return out


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_damaged_files_never_crash_a_handler(tmp_path: Path, name: str) -> None:
    path, data = SAMPLES[name]
    rng = random.Random(name)
    for index, variant in enumerate(_variants(data, rng)):
        root = write(tmp_path / str(index), {path: variant})
        errors = findings_of(inspect(root)).get("inventory.handler.error", [])
        assert not errors, (name, index, [e.detail for e in errors])


def test_unreadable_declarations_are_not_assessed(tmp_path: Path) -> None:
    """A runtime profile or MLmodel that is not valid YAML declares nothing. That is said as
    'not assessed', not reported as a handler fault."""
    files: dict[str, bytes | str] = {
        "runtime/chat.runtime.yaml": PROFILE[: PROFILE.index("server:") + 15],
        "model/MLmodel": "flavors: {python_function: {loader_module: mlflow.sklearn",
    }
    result = inspect(write(tmp_path / "d", files))
    gaps = {
        (f.rule, f.subject.display)
        for f in result.assessment.findings
        if f.result is Result.NOT_ASSESSED and "not valid YAML" in (f.not_assessed_reason or "")
    }
    assert ("runtime.component.missing", "runtime/chat.runtime.yaml") in gaps
    assert ("model.mlflow.custom-code", "model/MLmodel") in gaps
    assert "inventory.handler.error" not in findings_of(result)
