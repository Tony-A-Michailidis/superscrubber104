"""Repository mirrors as units: the chain from signed metadata to every package, and freshness.

The mirror handler checks each link where it finds it and claims what it checked. Here the links
are joined, per mirror root:

* an index (``primary.xml``, ``Packages``) is **chained** when metadata in the same mirror lists it
  and its hash matched. A dnf or apt index nothing lists is ``repo.metadata.unlisted``: whatever it
  says about packages is not vouched for;
* a package listed by a chained index under metadata verified with a pinned key gets a
  ``signature``-level verification naming that key's anchor. Any other listed package whose hash
  matched gets ``checksum`` level: the index travelled with it;
* listed packages that are not in the delivery are ``repo.content.missing``; listings that point
  at the network are ``repo.content.external``;
* metadata older than ``freshness.mirrors`` allows is ``repo.metadata.stale``.

What the mirror holds that no index lists (``repo.content.unlisted``) is decided in
``check_mirror_content`` once every artifact is known, and rollback against the last accepted
snapshot (``repo.metadata.rollback``) on the receiving side against its ledger.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from airlock import __version__
from airlock.core.canonical import JSON
from airlock.core.interfaces import Assembly, Context
from airlock.core.model import (
    Artifact,
    ArtifactRef,
    Result,
    Subject,
    SubjectKind,
    ToolRef,
    TrustLevel,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
    Verification,
)
from airlock.handlers.common import name_of, relative_to
from airlock.units.facts import as_str, strings

TOOL = ToolRef("airlock.repo-mirror", __version__)
_CHAINED_FORMATS = frozenset({"dnf", "apt"})
_CONTENT_SUFFIXES = {
    "dnf": (".rpm",),
    "apt": (".deb", ".udeb", ".ddeb"),
    "pypi": (".whl", ".tar.gz", ".zip", ".tar.bz2", ".egg"),
    "npm": (".tgz",),
    "helm": (".tgz",),
}
_METADATA_DIRS = ("repodata/", "dists/")


def _subject(root: ArtifactRef) -> Subject:
    return Subject(SubjectKind.UNIT, unit=f"{UnitKind.REPO_MIRROR.value}:{root.display}")


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class RepoMirrorAssembler:
    name = "repo-mirror"
    version = "1"
    kind = UnitKind.REPO_MIRROR

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for claim in claims:
            groups[claim.root].append(claim)
        return [_Mirror(root, group, ctx).assemble() for root, group in sorted(groups.items())]


class _Mirror:
    def __init__(self, root: ArtifactRef, claims: list[UnitClaim], ctx: Context) -> None:
        self.root, self.ctx = root, ctx
        self.metadata = [c for c in claims if c.role == "metadata"]
        self.indexes = [c for c in claims if c.role == "index"]
        self.content = [c for c in claims if c.role == "content"]
        # Index files whose hash matched what a metadata file lists, by path below the root.
        self.vouched: dict[str, UnitClaim] = {}
        by_path = {as_str(m.facts.get("path")): m for m in self.metadata}
        for claim in claims:
            if claim.role == "listed-index" and claim.facts.get("hashed"):
                meta = by_path.get(as_str(claim.facts.get("index")))
                path = as_str(claim.facts.get("path"))
                if meta is not None and path:
                    self.vouched[path] = meta
        formats = [as_str(c.facts.get("format")) for c in (*self.metadata, *self.indexes)]
        self.format = next((f for f in formats if f), "unknown")

    def assemble(self) -> Assembly:
        recorder = self.ctx.recorder
        chained = self._chain()
        verifications = self._verifications(chained)
        missing = sum(_int(c.facts.get("missing")) for c in self._content_indexes())
        external = sum(_int(c.facts.get("external")) for c in self._content_indexes())
        subject = _subject(self.root)
        if missing:
            sample: list[JSON] = []
            for c in self._content_indexes():
                sample.extend(strings(c.facts.get("missingSample")))
            recorder.fail(
                "repo.content.missing",
                subject,
                tool=TOOL,
                detail={"count": missing, "sample": sample[:50]},
            )
        else:
            recorder.passed("repo.content.missing")
        if external:
            recorder.fail(
                "repo.content.external",
                subject,
                tool=TOOL,
                detail={"count": external},
            )
        snapshots = self._freshness()
        signatures: dict[str, JSON] = {}
        for meta in self.metadata:
            signatures[as_str(meta.facts.get("path")) or name_of(meta.artifact)] = {
                "status": meta.facts.get("signature"),
                "anchor": meta.facts.get("anchor"),
            }
        attributes: dict[str, JSON] = {
            "format": self.format,
            "snapshots": dict(snapshots),
            "signatures": signatures,
            "indexes": len(self.indexes),
            "chainedIndexes": len(chained),
            "packages": len(self.content),
            "verifiedPackages": sum(
                1
                for c in self.content
                if c.artifact in verifications
                and verifications[c.artifact][0].level is TrustLevel.SIGNATURE
            ),
            "missing": missing,
            "external": external,
        }
        members = {
            (c.artifact, c.role): c.sha256 for c in (*self.metadata, *self.indexes, *self.content)
        }
        unit = Unit(
            kind=UnitKind.REPO_MIRROR,
            name=f"{self.format} mirror ({self.root.display})",
            root=self.root,
            members=tuple(
                UnitMember(role, ref, sha) for (ref, role), sha in sorted(members.items())
            ),
            attributes=attributes,
        )
        return Assembly(unit, verifications=verifications)

    def _content_indexes(self) -> list[UnitClaim]:
        """Indexes that list packages (Helm's index.yaml is both metadata and index)."""
        helm = [m for m in self.metadata if m.facts.get("format") == "helm"]
        return [*self.indexes, *helm]

    def _chain(self) -> dict[str, UnitClaim]:
        """Index path -> the metadata that vouches for it."""
        chained: dict[str, UnitClaim] = {}
        for index in self.indexes:
            path = as_str(index.facts.get("path")) or ""
            meta = self.vouched.get(path)
            if meta is not None:
                chained[path] = meta
                self.ctx.recorder.passed("repo.metadata.unlisted")
            elif index.facts.get("format") in _CHAINED_FORMATS:
                self.ctx.recorder.fail(
                    "repo.metadata.unlisted",
                    Subject.of_artifact(index.artifact),
                    tool=TOOL,
                    detail={
                        "reason": "no repository metadata here lists this index with this hash"
                        if self.metadata
                        else "the mirror has no repository metadata"
                    },
                )
        return chained

    def _verifications(
        self, chained: Mapping[str, UnitClaim]
    ) -> dict[ArtifactRef, tuple[Verification, ...]]:
        def signed(meta: UnitClaim, index: str | None) -> Verification:
            return Verification(
                "repo-metadata",
                TrustLevel.SIGNATURE,
                Result.PASS,
                signer=as_str(meta.facts.get("signer")),
                anchor=as_str(meta.facts.get("anchor")),
                detail={"metadata": meta.facts.get("path"), "index": index},
            )

        out: dict[ArtifactRef, tuple[Verification, ...]] = {}
        for index_claim in self.indexes:
            meta = chained.get(as_str(index_claim.facts.get("path")) or "")
            if meta is not None and meta.facts.get("signature") == "verified":
                out[index_claim.artifact] = (signed(meta, None),)
        for claim in self.content:
            if not claim.facts.get("hashed") or claim.facts.get("mismatch"):
                continue
            index = as_str(claim.facts.get("index")) or ""
            meta = chained.get(index)
            if meta is not None and meta.facts.get("signature") == "verified":
                out[claim.artifact] = (signed(meta, index),)
            else:
                out[claim.artifact] = (
                    Verification(
                        "repo-index",
                        TrustLevel.CHECKSUM,
                        Result.PASS,
                        anchor=index,
                        detail={"index": index},
                    ),
                )
        return out

    def _freshness(self) -> dict[str, str]:
        snapshots: dict[str, str] = {}
        limits = self.ctx.policy.mirror_max_age
        for meta in self.metadata:
            identity = as_str(meta.facts.get("identity"))
            when = _time(meta.facts.get("snapshot"))
            if identity is None or when is None:
                continue
            snapshots[identity] = as_str(meta.facts.get("snapshot")) or ""
            limit = limits.get(self.format, limits.get("default"))
            if limit is None:
                continue
            age = self.ctx.now - when
            if age > limit:
                self.ctx.recorder.fail(
                    "repo.metadata.stale",
                    Subject.of_artifact(meta.artifact),
                    tool=TOOL,
                    detail={
                        "snapshot": meta.facts.get("snapshot"),
                        "ageDays": age.days,
                        "maxAgeDays": limit.days,
                    },
                )
            else:
                self.ctx.recorder.passed("repo.metadata.stale")
        return snapshots


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def check_mirror_content(
    artifacts: Sequence[Artifact], units: Sequence[Unit], ctx: Context
) -> None:
    """Packages inside a mirror that no index lists: invisible to dnf, apt or pip, or smuggled."""
    mirrors = [u for u in units if u.kind is UnitKind.REPO_MIRROR]
    if not mirrors:
        return
    for unit in mirrors:
        suffixes = _CONTENT_SUFFIXES.get(str(unit.attributes.get("format")), ())
        members = {m.artifact for m in unit.members}
        unlisted: list[str] = []
        for artifact in artifacts:
            if artifact.ref.nested or artifact.ref in members:
                continue
            below = relative_to(artifact.ref, unit.root)
            if below is None or below.startswith(_METADATA_DIRS):
                continue
            if below.endswith(suffixes):
                unlisted.append(below)
        if unlisted:
            ctx.recorder.fail(
                "repo.content.unlisted",
                _subject(unit.root),
                tool=TOOL,
                detail={"count": len(unlisted), "files": unlisted[:200]},
            )
        else:
            ctx.recorder.passed("repo.content.unlisted")
