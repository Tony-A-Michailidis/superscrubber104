"""Knowledge bases: vector indexes and stores, and the text they hold.

Recognised stores, each read statically:

* **FAISS** index files (header: type, dimension, vector count, metric), and LangChain's
  ``save_local`` layout (``index.faiss`` + ``index.pkl``, whose pickled docstore gets the pickle
  checks like any other pickle).
* **Chroma** persistent directories: ``chroma.sqlite3`` is opened from memory, read-only, with
  trusted schema off, and only its own tables are queried (collections, dimensions, embedding
  function configuration, counts, documents). HNSW segment directories, including the older
  pickled ``index_metadata.pickle``, belong to the same unit.
* **LlamaIndex** storage contexts (``docstore.json``, ``index_store.json``, ``*vector_store.json``,
  ``graph_store.json``).
* **LanceDB** tables (``*.lance`` directories) and **Qdrant** snapshots: recognised and grouped;
  their contents are not read.

Stored documents are scanned for instructions aimed at a model and for invisible characters:
retrieved text goes straight into a model's context, so this is where a data-borne prompt
injection waits. Units, and the link to the embedding model, are formed by the knowledge-base
assembler.
"""

import json
import re
import sqlite3
from collections.abc import Callable, Iterable

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, ToolRef, UnitClaim, UnitKind
from airlock.formats.faiss import looks_like_faiss, read_faiss
from airlock.handlers.common import (
    TooLarge,
    make_claim,
    name_of,
    parent_of,
    read_bytes,
    read_json,
)
from airlock.text import scan_text

TOOL = ToolRef("airlock.knowledge", __version__)
_SQLITE_LIMIT = 512 << 20
_JSON_LIMIT = 256 << 20
_CORPUS_LIMIT = 64 << 20  # characters of stored text scanned per store
_MAX_DOCUMENTS = 500_000
_CHROMA_SEGMENT = frozenset(
    {"header.bin", "data_level0.bin", "length.bin", "link_lists.bin", "index_metadata.pickle"}
)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_LLAMA = re.compile(r"^(?:[\w-]+__)?(vector_store|docstore|index_store|graph_store)\.json$")
_FIRST_VECTOR = re.compile(rb'"embedding_dict"\s*:\s*\{\s*"[^"]*"\s*:\s*\[([^\]]*)\]')
_CORPUS_RULES = ("kb.corpus.injection", "kb.corpus.hidden-characters")


def _claim(view: ArtifactView, role: str, facts: dict[str, object], root_up: int = 1) -> UnitClaim:
    root = view.ref
    for _ in range(root_up):
        root = parent_of(root)
    return make_claim(view, UnitKind.KNOWLEDGE_BASE, role, facts, root=root)


def scan_corpus(
    ctx: Context, view: ArtifactView, documents: Iterable[tuple[str, str]], store: str
) -> int:
    """Scan stored documents (id, text) for injected instructions; returns how many were read."""
    injections: list[dict[str, str]] = []
    hidden: list[dict[str, object]] = []
    read = chars = 0
    for doc_id, text in documents:
        read += 1
        chars += len(text)
        report = scan_text(text)
        for reason, excerpt in report.injections[:3]:
            injections.append({"document": doc_id[:120], "reason": reason, "excerpt": excerpt})
        if report.invisible:
            hidden.append({"document": doc_id[:120], "characters": list(report.invisible)})
        if chars > _CORPUS_LIMIT or read >= _MAX_DOCUMENTS:
            ctx.recorder.not_assessed(
                _CORPUS_RULES,
                Subject.of_artifact(view.ref, locator="remaining documents"),
                tool=TOOL,
                reason=f"only the first {read} documents were scanned",
            )
            break
    subject = Subject.of_artifact(view.ref, locator="documents")
    for rule, hits, key in (
        ("kb.corpus.injection", injections, "matches"),
        ("kb.corpus.hidden-characters", hidden, "documents"),
    ):
        if hits:
            ctx.recorder.fail(
                rule,
                subject,
                tool=TOOL,
                detail={
                    "store": store,
                    "documentsScanned": read,
                    key: hits[:50],
                    "total": len(hits),
                },
            )
        else:
            ctx.recorder.passed(rule)
    return read


# --- stores -------------------------------------------------------------------------------------


def _faiss(view: ArtifactView, ctx: Context) -> Inspection:
    info = read_faiss(view.head(64), view.size)
    facts = {
        "store": "faiss",
        "indexType": info.type_code,
        "dimension": info.dimension,
        "vectors": info.vectors,
        "metric": info.metric,
        "trained": info.trained,
    }
    if info.problem:
        ctx.recorder.fail(
            "kb.index.malformed",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"problem": info.problem},
        )
    else:
        ctx.recorder.passed("kb.index.malformed")
    return Inspection(
        kind="kb.faiss-index",
        metadata={"vectorIndex": facts},
        claims=(_claim(view, "vector-index", facts),),
    )


def _langchain_docstore(view: ArtifactView, ctx: Context) -> Inspection:
    return Inspection(
        kind="kb.langchain-docstore",
        claims=(_claim(view, "docstore", {"store": "langchain-faiss", "format": "pickle"}),),
    )


def _chroma_rows(
    con: sqlite3.Connection, query: str, params: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    return list(con.execute(query, params).fetchall())


def _chroma(view: ArtifactView, ctx: Context) -> Inspection:
    subject = Subject.of_artifact(view.ref)
    facts: dict[str, object] = {"store": "chroma"}
    try:
        data = read_bytes(view, _SQLITE_LIMIT)
    except TooLarge as exc:
        ctx.recorder.not_assessed(
            ("kb.index.malformed", *_CORPUS_RULES), subject, tool=TOOL, reason=str(exc)
        )
        return Inspection(kind="kb.chroma", claims=(_claim(view, "chroma-db", facts),))
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(data)
        con.execute("PRAGMA trusted_schema = OFF")
        con.execute("PRAGMA query_only = ON")
        tables = {
            str(r[0])
            for r in _chroma_rows(con, "SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "collections" not in tables:
            raise sqlite3.DatabaseError("no collections table: not a Chroma database")
        columns = {str(r[1]) for r in _chroma_rows(con, "PRAGMA table_info(collections)")}
        config_column = next(
            (c for c in ("configuration_json_str", "config_json_str") if c in columns), None
        )
        # config_column is one of two fixed names, never input from the file
        extra = f", {config_column}" if config_column else ""
        select = f"SELECT name, dimension{extra} FROM collections"  # noqa: S608
        collections = []
        for row in _chroma_rows(con, select):
            config = _json(row[2]) if config_column else {}
            collections.append(
                {
                    "name": str(row[0]),
                    "dimension": row[1] if isinstance(row[1], int) else None,
                    "embeddingModel": _embedding_model(config),
                    "space": _space(config),
                }
            )
        facts["collections"] = collections
        if "embeddings" in tables:
            facts["vectors"] = _chroma_rows(con, "SELECT count(*) FROM embeddings")[0][0]
        documents: list[tuple[str, str]] = []
        if "embedding_metadata" in tables:
            documents = [
                (str(r[0]), str(r[1]))
                for r in _chroma_rows(
                    con,
                    "SELECT coalesce(e.embedding_id, m.id), m.string_value "
                    "FROM embedding_metadata m LEFT JOIN embeddings e ON e.id = m.id "
                    "WHERE m.key = 'chroma:document' LIMIT ?",
                    (_MAX_DOCUMENTS,),
                )
                if r[1] is not None
            ]
        if "migrations" in tables:
            facts["migrations"] = _chroma_rows(con, "SELECT count(*) FROM migrations")[0][0]
    except sqlite3.DatabaseError as exc:
        ctx.recorder.fail(
            "kb.index.malformed", subject, tool=TOOL, detail={"problem": str(exc)[:300]}
        )
        return Inspection(kind="kb.chroma", claims=(_claim(view, "chroma-db", facts),))
    finally:
        con.close()
    ctx.recorder.passed("kb.index.malformed")
    facts["documents"] = scan_corpus(ctx, view, documents, "chroma")
    return Inspection(
        kind="kb.chroma",
        metadata={"vectorStore": facts},
        claims=(_claim(view, "chroma-db", facts),),
    )


def _json(value: object) -> dict[str, object]:
    try:
        data = json.loads(str(value)) if value else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _embedding_model(config: dict[str, object]) -> str | None:
    function = config.get("embedding_function")
    if not isinstance(function, dict):
        return None
    inner = function.get("config")
    if isinstance(inner, dict):
        for key in ("model_name", "model", "model_id"):
            if isinstance(inner.get(key), str):
                return str(inner[key])
    name = function.get("name")
    if name == "default":  # Chroma downloads this ONNX model on first use
        return "all-MiniLM-L6-v2 (Chroma default embedding function)"
    return f"{name} (default model)" if isinstance(name, str) else None


def _space(config: dict[str, object]) -> str | None:
    for key in ("hnsw", "hnsw_configuration", "spann"):
        section = config.get(key)
        if isinstance(section, dict) and isinstance(section.get("space"), str):
            return str(section["space"])
    return None


def _chroma_segment(view: ArtifactView, ctx: Context) -> Inspection:
    return Inspection(
        kind="kb.chroma-segment",
        claims=(_claim(view, "chroma-segment", {"segment": name_of(parent_of(view.ref))}, 2),),
    )


def _llamaindex(view: ArtifactView, ctx: Context) -> Inspection:
    match = _LLAMA.match(name_of(view.ref))
    assert match is not None  # noqa: S101 - only dispatched on a match
    part = match.group(1)
    facts: dict[str, object] = {"store": "llamaindex", "part": part}
    if part == "vector_store":
        found = _FIRST_VECTOR.search(view.head(4 << 20))
        if found:
            facts["dimension"] = found.group(1).count(b",") + 1 if found.group(1).strip() else 0
    elif part == "docstore":
        try:
            data = read_json(view, _JSON_LIMIT)
        except (TooLarge, ValueError, UnicodeDecodeError) as exc:
            ctx.recorder.not_assessed(
                _CORPUS_RULES, Subject.of_artifact(view.ref), tool=TOOL, reason=str(exc)[:300]
            )
            data = {}
        nodes = data.get("docstore/data") if isinstance(data, dict) else None
        nodes = nodes if isinstance(nodes, dict) else {}
        documents = [
            (str(node_id), str(inner["text"]))
            for node_id, node in nodes.items()
            if isinstance(node, dict)
            and isinstance(inner := node.get("__data__"), dict)
            and isinstance(inner.get("text"), str)
        ]
        facts["documents"] = scan_corpus(ctx, view, documents, "llamaindex")
    return Inspection(
        kind=f"kb.llamaindex-{part.replace('_', '-')}",
        metadata={"vectorStore": facts},
        claims=(_claim(view, f"llamaindex-{part.replace('_', '-')}", facts),),
    )


def _lance(view: ArtifactView, ctx: Context) -> Inspection:
    table = parent_of(parent_of(view.ref))
    role = "lance-manifest" if name_of(parent_of(view.ref)) == "_versions" else "lance-data"
    return Inspection(
        kind="kb.lancedb",
        claims=(make_claim(view, UnitKind.KNOWLEDGE_BASE, role, {"store": "lancedb"}, root=table),),
    )


def _qdrant(view: ArtifactView, ctx: Context) -> Inspection:
    facts = {"store": "qdrant", "note": "snapshot contents are not inspected"}
    return Inspection(
        kind="kb.qdrant-snapshot",
        claims=(
            make_claim(view, UnitKind.KNOWLEDGE_BASE, "qdrant-snapshot", facts, root=view.ref),
        ),
    )


def _dispatch(view: ArtifactView) -> Callable[[ArtifactView, Context], Inspection] | None:
    name = name_of(view.ref)
    lowered = name.lower()
    head = view.head(512)
    if looks_like_faiss(head):
        return _faiss
    if name == "index.pkl" and view.resolve("index.faiss") is not None:
        return _langchain_docstore
    if name == "chroma.sqlite3" and head.startswith(b"SQLite format 3\x00"):
        return _chroma
    if (
        name in _CHROMA_SEGMENT
        and _UUID.match(name_of(parent_of(view.ref)))
        and view.resolve("../chroma.sqlite3") is not None
    ):
        return _chroma_segment
    if _LLAMA.match(name) and head.lstrip().startswith(b"{"):
        return _llamaindex
    path = view.ref.display
    if ".lance/" in path and (lowered.endswith(".manifest") or lowered.endswith(".lance")):
        return _lance
    if lowered.endswith(".snapshot") and head[257:262] == b"ustar":
        return _qdrant
    return None


class KnowledgeBaseHandler:
    name = "knowledge"
    version = "1"
    kinds = frozenset(
        {
            "kb.faiss-index",
            "kb.langchain-docstore",
            "kb.chroma",
            "kb.chroma-segment",
            "kb.llamaindex-vector-store",
            "kb.llamaindex-docstore",
            "kb.llamaindex-index-store",
            "kb.llamaindex-graph-store",
            "kb.lancedb",
            "kb.qdrant-snapshot",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        handler = _dispatch(artifact)
        return Detection("kb", 70) if handler else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handler = _dispatch(artifact)
        assert handler is not None  # noqa: S101 - only called after detect()
        return handler(artifact, ctx)
