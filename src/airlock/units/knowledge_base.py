"""Knowledge-base units, and their link to the embedding model that built them.

A knowledge base is a vector store and what belongs to it: a FAISS index with its LangChain
docstore, a Chroma directory with its segments, a LlamaIndex storage context, a LanceDB table, a
Qdrant snapshot. The unit records the store, dimension, vector and document counts, metric and,
where the store records it, the embedding model.

Queries must be embedded by the model that built the index, so the link matters:

* a store that names its model (Chroma's embedding function configuration) must find that model
  among the delivery's model packages (``kb.embedding-model.missing``), with the same dimension
  (``kb.embedding-model.mismatch``);
* a store that does not name it (FAISS, LlamaIndex, LangChain) is reported at low severity with
  the delivered embedding models whose dimension matches, so a reviewer can confirm the pairing.

The link is made after every unit is assembled, by ``link_knowledge_bases``.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import replace

from airlock import __version__
from airlock.core.canonical import JSON, jsonable
from airlock.core.interfaces import Assembly, Context
from airlock.core.model import (
    ArtifactRef,
    Requirement,
    Subject,
    ToolRef,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
)
from airlock.handlers.common import name_of
from airlock.units.facts import as_dict, as_int, as_list, as_str, opt_int

TOOL = ToolRef("airlock.knowledge-base", __version__)
_CORE = frozenset(
    {
        "vector-index", "chroma-db", "llamaindex-vector-store", "llamaindex-docstore",
        "llamaindex-index-store", "lance-manifest", "qdrant-snapshot",
    }
)  # fmt: skip


class KnowledgeBaseAssembler:
    name = "knowledge-base"
    version = __version__
    kind = UnitKind.KNOWLEDGE_BASE

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for c in claims:
            groups[c.root].append(c)
        for root in sorted(groups):
            group = groups[root]
            if any(c.role in _CORE for c in group):
                yield Assembly(self._unit(root, group))

    def _unit(self, root: ArtifactRef, claims: list[UnitClaim]) -> Unit:
        stores = sorted({s for c in claims if (s := as_str(c.facts.get("store")))})
        dimensions: set[int] = set()
        models: set[str] = set()
        vectors = documents = 0
        metric = None
        for c in claims:
            if (d := opt_int(c.facts.get("dimension"))) is not None:
                dimensions.add(d)
            vectors += as_int(c.facts.get("vectors")) or 0
            documents += as_int(c.facts.get("documents")) or 0
            metric = metric or as_str(c.facts.get("metric"))
            for collection in as_list(c.facts.get("collections")):
                info = as_dict(collection)
                if (d := opt_int(info.get("dimension"))) is not None:
                    dimensions.add(d)
                if model := as_str(info.get("embeddingModel")):
                    models.add(model)
                metric = metric or as_str(info.get("space"))
        attributes: dict[str, JSON] = {
            "stores": jsonable(stores),
            "dimensions": jsonable(sorted(dimensions)),
            "vectors": vectors or None,
            "documents": documents or None,
            "metric": metric,
            "embeddingModels": jsonable(sorted(models)),
            "collections": jsonable(
                [as_dict(x) for c in claims for x in as_list(c.facts.get("collections"))]
            ),
        }
        members = tuple(
            sorted(
                {UnitMember(c.role, c.artifact, c.sha256) for c in claims},
                key=lambda m: (m.artifact.display, m.role),
            )
        )
        name = name_of(root) if root.path != "." else "knowledge base"
        return Unit(
            kind=UnitKind.KNOWLEDGE_BASE,
            name=name,
            root=root,
            members=members,
            attributes={k: v for k, v in attributes.items() if v not in (None, [], {})},
        )


def _aliases(unit: Unit) -> set[str]:
    names = {unit.name, name_of(unit.root)}
    return {n.lower().rsplit("/", 1)[-1] for n in names if n}


def _dimension(unit: Unit) -> int | None:
    return opt_int(as_dict(unit.attributes.get("embedding")).get("dimension"))


def link_knowledge_bases(units: Sequence[Unit], ctx: Context) -> list[Unit]:
    """Attach each knowledge base's embedding-model requirement and check it."""
    models = [u for u in units if u.kind is UnitKind.MODEL_PACKAGE]
    embedders = [u for u in models if _dimension(u) is not None]
    linked: list[Unit] = []
    for unit in units:
        if unit.kind is not UnitKind.KNOWLEDGE_BASE:
            linked.append(unit)
            continue
        subject = Subject.of_unit(unit)
        dimensions = [
            int(d) for d in as_list(unit.attributes.get("dimensions")) if isinstance(d, int)
        ]
        named = [str(m) for m in as_list(unit.attributes.get("embeddingModels"))]
        requires: list[Requirement] = []
        if not named:
            candidates = [u.id for u in embedders if _dimension(u) in dimensions]
            ctx.recorder.fail(
                "kb.embedding-model.unrecorded",
                subject,
                tool=TOOL,
                detail={"dimensions": dimensions, "candidates": candidates},
            )
            requires.append(Requirement("embedding-model", "unrecorded", UnitKind.MODEL_PACKAGE))
        else:
            ctx.recorder.passed("kb.embedding-model.unrecorded")
        for model in named:
            key = model.split(" (", 1)[0].lower().rsplit("/", 1)[-1]
            match = next((u for u in models if key in _aliases(u)), None)
            requires.append(
                Requirement(
                    "embedding-model",
                    model,
                    UnitKind.MODEL_PACKAGE,
                    satisfied_by=match.id if match else None,
                )
            )
            if match is None:
                ctx.recorder.fail(
                    "kb.embedding-model.missing",
                    subject,
                    tool=TOOL,
                    detail={"model": model},
                    discriminator=model,
                )
                continue
            ctx.recorder.passed("kb.embedding-model.missing")
            width = _dimension(match)
            if width is not None and dimensions and width not in dimensions:
                ctx.recorder.fail(
                    "kb.embedding-model.mismatch",
                    subject,
                    tool=TOOL,
                    detail={
                        "model": match.id,
                        "modelDimension": width,
                        "indexDimensions": dimensions,
                    },
                    discriminator=model,
                )
            else:
                ctx.recorder.passed("kb.embedding-model.mismatch")
        linked.append(replace(unit, requires=(*unit.requires, *requires)))
    return linked
