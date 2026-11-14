"""Datasets: data files, Hugging Face dataset layouts and cards, loading scripts.

* **Parquet**: the footer is read statically (schema, rows, writer, metadata keys) and its column
  chunks are checked to lie inside the file.
* **Arrow** IPC files and streams (what ``datasets.save_to_disk`` writes), **JSON Lines**, **CSV**
  and **TSV**: recognised, with a row count and the first record's fields or the header.
* Hugging Face layouts: dataset cards (``README.md`` with dataset front matter, including the
  ``configs`` that name data files), ``state.json``, ``dataset_info.json`` and
  ``dataset_dict.json`` from ``save_to_disk``.
* **Loading scripts** (a ``GeneratorBasedBuilder`` next to the data): running one is running
  arbitrary code, and it usually downloads the data when it runs.

Handlers report files; the dataset assembler forms ``dataset`` units around cards and
``save_to_disk`` metadata and checks that every file they name is present.
"""

import csv
import io
import json
import re
from collections.abc import Callable
from typing import Any

import yaml

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, ToolRef, UnitClaim, UnitKind
from airlock.core.yamlio import load_untrusted_yaml
from airlock.formats.parquet import ParquetError, read_parquet
from airlock.handlers.common import TooLarge, make_claim, name_of, parent_of, read_json, read_text

TOOL = ToolRef("airlock.datasets", __version__)
_COUNT_LIMIT = 1 << 30  # rows are counted in files up to this size
_DATASET_KEYS = frozenset(
    {
        "dataset_info", "configs", "task_categories", "size_categories", "task_ids",
        "annotations_creators", "language_creators", "source_datasets", "multilinguality",
        "pretty_name", "paperswithcode_id",
    }
)  # fmt: skip
_MODEL_KEYS = frozenset({"pipeline_tag", "library_name", "base_model", "model-index", "model_name"})
_BUILDER = re.compile(rb"\b(?:GeneratorBasedBuilder|ArrowBasedBuilder|DatasetBuilder)\b")
_IMPORTS_DATASETS = re.compile(rb"^\s*(?:import datasets|from datasets import)", re.M)
_DATA_EXTENSIONS = {".jsonl": "jsonl", ".ndjson": "jsonl", ".csv": "csv", ".tsv": "tsv"}
Reader = Callable[[ArtifactView, Context], Inspection]


def is_dataset_card(front: dict[Any, Any]) -> bool:
    keys = {str(k) for k in front}
    return bool(keys & _DATASET_KEYS) and not keys & _MODEL_KEYS


def _front_matter(text: str) -> dict[Any, Any] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if not 0 < end < 256 * 1024:
        return None
    try:
        front = load_untrusted_yaml(text[3:end])
    except yaml.YAMLError:
        return None
    return front if isinstance(front, dict) else None


def _claim(view: ArtifactView, role: str, facts: dict[str, object]) -> UnitClaim:
    return make_claim(view, UnitKind.DATASET, role, facts, root=parent_of(view.ref))


def _malformed(ctx: Context, view: ArtifactView, problems: list[str]) -> None:
    if problems:
        ctx.recorder.fail(
            "dataset.file.malformed",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"problems": problems[:20]},
        )
    else:
        ctx.recorder.passed("dataset.file.malformed")


# --- data files ---------------------------------------------------------------------------------


def _parquet(view: ArtifactView, ctx: Context) -> Inspection:
    facts: dict[str, object] = {"format": "parquet", "file": name_of(view.ref)}
    try:
        with view.open() as stream:
            info = read_parquet(stream, view.size)
    except (ParquetError, OSError) as exc:
        _malformed(ctx, view, [str(exc)])
        return Inspection(kind="dataset.parquet", claims=(_claim(view, "data", facts),))
    facts.update(
        rows=info.rows,
        columns=list(info.columns[:200]),
        rowGroups=info.row_groups,
        createdBy=info.created_by,
        metadataKeys=list(info.metadata_keys),
    )
    _malformed(ctx, view, list(info.problems))
    return Inspection(
        kind="dataset.parquet", metadata={"dataset": facts}, claims=(_claim(view, "data", facts),)
    )


def _arrow(view: ArtifactView, ctx: Context) -> Inspection:
    head = view.head(8)
    layout = "file" if head.startswith(b"ARROW1") else "stream"
    facts: dict[str, object] = {"format": "arrow", "layout": layout, "file": name_of(view.ref)}
    return Inspection(
        kind="dataset.arrow", metadata={"dataset": facts}, claims=(_claim(view, "data", facts),)
    )


def _lines(view: ArtifactView, fmt: str, ctx: Context) -> Inspection:
    facts: dict[str, object] = {"format": fmt, "file": name_of(view.ref)}
    problems: list[str] = []
    rows = 0
    first: bytes | None = None
    with view.open() as stream:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            rows += 1
            if first is None:
                first = line
            if fmt == "jsonl" and number <= 1000:
                try:
                    json.loads(line)
                except ValueError:
                    problems.append(f"line {number} is not valid JSON")
            if stream.tell() > _COUNT_LIMIT:
                rows = -1
                break
    if fmt == "jsonl" and first is not None:
        try:
            record = json.loads(first)
            if isinstance(record, dict):
                facts["fields"] = [str(k) for k in list(record)[:200]]
        except ValueError:
            pass
    elif first is not None:
        delimiter = "\t" if fmt == "tsv" else ","
        header = next(
            csv.reader(io.StringIO(first.decode("utf-8", "replace")), delimiter=delimiter)
        )
        facts["columns"] = header[:200]
        rows -= 1  # the header
    facts["rows"] = rows if rows >= 0 else None
    if fmt == "jsonl":
        _malformed(ctx, view, problems)
    return Inspection(
        kind=f"dataset.{'csv' if fmt == 'tsv' else fmt}",
        metadata={"dataset": facts},
        claims=(_claim(view, "data", facts),),
    )


# --- metadata -----------------------------------------------------------------------------------


def _card(view: ArtifactView, ctx: Context) -> Inspection:
    front = _front_matter(read_text(view, 4 << 20)) or {}
    configs = []
    for config in front.get("configs") or []:
        if not isinstance(config, dict):
            continue
        files = config.get("data_files")
        patterns: list[str] = []
        for item in files if isinstance(files, list) else [files]:
            if isinstance(item, str):
                patterns.append(item)
            elif isinstance(item, dict):
                path = item.get("path")
                patterns.extend(
                    p for p in (path if isinstance(path, list) else [path]) if isinstance(p, str)
                )
        configs.append({"name": str(config.get("config_name", "default")), "dataFiles": patterns})
    licence = front.get("license")
    facts = {
        "prettyName": front.get("pretty_name")
        if isinstance(front.get("pretty_name"), str)
        else None,
        "license": licence if isinstance(licence, str | list) else None,
        "licenseName": front.get("license_name")
        if isinstance(front.get("license_name"), str)
        else None,
        "taskCategories": front.get("task_categories")
        if isinstance(front.get("task_categories"), list)
        else None,
        "configs": configs,
        "gated": any(str(k).startswith("extra_gated") for k in front),
    }
    return Inspection(kind="dataset.card", claims=(_claim(view, "card", facts),))


def _hf_metadata(view: ArtifactView, ctx: Context) -> Inspection:
    name = name_of(view.ref)
    try:
        data = read_json(view, 16 << 20)
    except (TooLarge, ValueError, UnicodeDecodeError):
        data = {}
    data = data if isinstance(data, dict) else {}
    if name == "state.json":
        files = [f.get("filename") for f in data.get("_data_files") or [] if isinstance(f, dict)]
        facts: dict[str, object] = {
            "dataFiles": [f for f in files if isinstance(f, str)],
            "fingerprint": data.get("_fingerprint"),
            "split": data.get("_split"),
        }
        return Inspection(kind="dataset.hf-state", claims=(_claim(view, "state", facts),))
    if name == "dataset_dict.json":
        splits = data.get("splits")
        facts = {
            "splits": [s for s in splits if isinstance(s, str)] if isinstance(splits, list) else []
        }
        return Inspection(kind="dataset.hf-dict", claims=(_claim(view, "dict", facts),))
    features = data.get("features")
    splits = data.get("splits")
    facts = {
        "features": list(features)[:200] if isinstance(features, dict) else None,
        "splits": {
            str(k): v.get("num_examples")
            for k, v in splits.items()
            if isinstance(v, dict) and isinstance(v.get("num_examples"), int)
        }
        if isinstance(splits, dict)
        else None,
        "license": data.get("license") or None,
        "builder": data.get("builder_name"),
    }
    return Inspection(kind="dataset.hf-info", claims=(_claim(view, "info", facts),))


def _loading_script(view: ArtifactView, ctx: Context) -> Inspection:
    text = read_text(view, 4 << 20)
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>)]+", text)))[:20]
    ctx.recorder.fail(
        "dataset.remote-code.required",
        Subject.of_artifact(view.ref),
        tool=TOOL,
        detail={"script": name_of(view.ref), "downloads": urls},
    )
    return Inspection(
        kind="dataset.loading-script",
        claims=(_claim(view, "loading-script", {"script": name_of(view.ref), "urls": urls}),),
    )


def _dispatch(view: ArtifactView) -> Reader | str | None:
    name = name_of(view.ref)
    lowered = name.lower()
    head = view.head(65536)
    if head.startswith(b"PAR1"):
        return _parquet
    if head.startswith(b"ARROW1") or (
        lowered.endswith(".arrow") and head[:4] == b"\xff\xff\xff\xff"
    ):
        return _arrow
    extension = lowered[lowered.rfind(".") :] if "." in lowered else ""
    if extension in _DATA_EXTENSIONS and b"\x00" not in head:
        return _DATA_EXTENSIONS[extension]
    hf_metadata = name in ("state.json", "dataset_dict.json", "dataset_info.json")
    if (
        hf_metadata
        and head.lstrip().startswith(b"{")
        and (name != "state.json" or b"_data_files" in head)
    ):
        return _hf_metadata
    if lowered == "readme.md" and head.startswith(b"---"):
        front = _front_matter(head.decode("utf-8", "replace"))
        if front is not None and is_dataset_card(front):
            return _card
    if lowered.endswith(".py") and _BUILDER.search(head) and _IMPORTS_DATASETS.search(head):
        return _loading_script
    return None


class DatasetHandler:
    name = "datasets"
    version = "1"
    kinds = frozenset(
        {
            "dataset.parquet",
            "dataset.arrow",
            "dataset.jsonl",
            "dataset.csv",
            "dataset.card",
            "dataset.hf-state",
            "dataset.hf-dict",
            "dataset.hf-info",
            "dataset.loading-script",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("dataset", 60) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handler = _dispatch(artifact)
        assert handler is not None  # noqa: S101 - only called after detect()
        if isinstance(handler, str):
            return _lines(artifact, handler, ctx)
        return handler(artifact, ctx)
