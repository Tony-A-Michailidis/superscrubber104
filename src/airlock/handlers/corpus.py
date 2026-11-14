"""Folders of documents that a knowledge base will be built from.

Nothing in a folder of Markdown, PDFs or Word files says that it will be fed to a model, so
airlock is told: a transfer request content entry with ``unit: knowledge-base`` (or ``--corpus``
on ``airlock model inspect`` and ``airlock offline-check``) marks its paths as a corpus. Every
document under them, including documents inside archives there, is read the way a retrieval
pipeline would read it and scanned like the stored text of a vector store: for instructions aimed
at a model, invisible characters, and constructs that hide text from a human reviewer.

The documents form a ``knowledge-base`` unit (store ``corpus``) rooted at the declared folder, so
the embedding-model link and the request's unit check apply as for any other knowledge base.
"""

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import UNCLASSIFIED, ArtifactRef, Subject, ToolRef, UnitKind
from airlock.core.paths import has_glob, path_matches
from airlock.formats.doctext import DOCUMENTS, OFFICE, extract, suffix
from airlock.handlers.common import full_path, make_claim, name_of
from airlock.handlers.knowledge import scan_corpus

TOOL = ToolRef("airlock.corpus", __version__)
_RULES = ("kb.corpus.injection", "kb.corpus.hidden-characters", "kb.corpus.hidden-text")


def corpus_root(pattern: str) -> str:
    """The folder a corpus pattern names: its path up to the first wildcard."""
    if not has_glob(pattern):
        return pattern.rstrip("/") or "."
    static = pattern[: min(pattern.find(c) for c in "*?[" if c in pattern)]
    return static.rsplit("/", 1)[0] if "/" in static else "."


def matching_corpus(ref: ArtifactRef, corpora: tuple[str, ...]) -> str | None:
    """The corpus pattern that covers ``ref`` (by its top-level path), if any."""
    for pattern in corpora:
        if path_matches(pattern, ref.path) or (
            not has_glob(pattern) and ref.path.startswith(pattern.rstrip("/") + "/")
        ):
            return pattern
    return None


class CorpusHandler:
    """Reads documents only when they lie in a declared corpus; otherwise does nothing."""

    name = "corpus"
    version = "1"
    kinds = frozenset({"kb.corpus-document"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if suffix(name_of(artifact.ref)) in DOCUMENTS:
            return Detection(UNCLASSIFIED, 0)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        pattern = matching_corpus(artifact.ref, ctx.corpora)
        ref = artifact.ref
        container = (ref.path, *ref.member)[-2] if ref.member else ""
        if pattern is None or suffix(container) in OFFICE:  # an Office file is read whole
            return Inspection(kind=UNCLASSIFIED)
        subject = Subject.of_artifact(artifact.ref)
        with artifact.open() as stream:
            extracted = extract(name_of(artifact.ref), stream)
        facts: dict[str, object] = {
            "store": "corpus",
            "documents": 1,
            "format": suffix(name_of(artifact.ref)).lstrip("."),
        }
        if extracted.problem:
            ctx.recorder.not_assessed(_RULES, subject, tool=TOOL, reason=extracted.problem)
        else:
            scan_corpus(ctx, artifact, [(full_path(artifact.ref), extracted.text)], "corpus")
            if extracted.hidden:
                ctx.recorder.fail(
                    "kb.corpus.hidden-text",
                    subject,
                    tool=TOOL,
                    detail={"constructs": extracted.hidden},
                )
            else:
                ctx.recorder.passed("kb.corpus.hidden-text")
        root = ArtifactRef(corpus_root(pattern))
        claim = make_claim(artifact, UnitKind.KNOWLEDGE_BASE, "corpus-document", facts, root=root)
        return Inspection(
            kind="kb.corpus-document",
            metadata={"corpus": {"characters": len(extracted.text), "hidden": extracted.hidden}},
            claims=(claim,),
        )
