"""Interpretation of content: run handlers on every artifact and look inside archives.

Archives are inspected, never extracted. Member bytes are streamed through a hash; a member is
written to a private, randomly named scratch file only when something needs to read it again (a
nested archive, or a handler that recognised it). Member names never touch the filesystem.

A single budget covers one top-level artifact and everything nested inside it, and counts bytes
actually produced rather than sizes declared in headers, so decompression bombs stop inspection
at the policy limit however they are nested.
"""

import posixpath
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import IO

from airlock import __version__
from airlock.archive import (
    ARCHIVE_ERRORS,
    COMPRESSION,
    UNSUPPORTED,
    Member,
    decompress,
    detect_format,
    members,
)
from airlock.catalog import ARCHIVE_MEMBER_RULES
from airlock.core.canonical import jsonable
from airlock.core.interfaces import ArtifactView, Context, Handler
from airlock.core.model import (
    UNCLASSIFIED,
    Artifact,
    ArtifactRef,
    Component,
    EntryType,
    Severity,
    Subject,
    ToolRef,
    UnitClaim,
)
from airlock.core.paths import NameIssue, check_member_name, link_escapes
from airlock.core.policy import ArchiveLimits
from airlock.hashing import hash_stream
from airlock.walker import FileView, HeadView

TOOL = ToolRef("airlock", __version__)
_ROOTFS_DIRS = frozenset(
    {"bin", "sbin", "etc", "usr", "lib", "lib64", "var", "opt", "root", "home"}
)
_HEAD = 65536
_SUFFIXES = (".gz", ".bz2", ".xz")


class LimitExceeded(Exception):
    def __init__(self, limit: str) -> None:
        super().__init__(limit)
        self.limit = limit
        self.where: ArtifactRef | None = None


class Budget:
    """Expansion allowance for one top-level artifact and everything nested in it."""

    def __init__(self, limits: ArchiveLimits, outer_size: int) -> None:
        self.limits = limits
        self.outer_size = max(outer_size, 1)
        self.expanded = 0
        self.members = 0

    def member(self) -> None:
        self.members += 1
        if self.members > self.limits.max_members:
            raise LimitExceeded("members")

    def consume(self, count: int) -> None:
        self.expanded += count
        if self.expanded > self.limits.max_expanded_bytes:
            raise LimitExceeded("expanded-size")
        if (
            self.expanded > self.limits.ratio_min_bytes
            and self.expanded > self.outer_size * self.limits.max_ratio
        ):
            raise LimitExceeded("ratio")


class _Prefixed:
    """Replays bytes already read from a stream, then continues with the stream."""

    def __init__(self, prefix: bytes, stream: IO[bytes]) -> None:
        self._prefix = prefix
        self._stream = stream

    def read(self, n: int, /) -> bytes:
        if self._prefix:
            data, self._prefix = self._prefix[:n], self._prefix[n:]
            return data
        return self._stream.read(n)


class Analyzer:
    def __init__(self, ctx: Context, handlers: Sequence[Handler], workdir: Path) -> None:
        self.ctx = ctx
        self.handlers = tuple(handlers)
        self.artifacts: list[Artifact] = []
        self.claims: list[UnitClaim] = []
        self.components: list[Component] = []
        self._workdir = workdir
        self._scratch = 0

    # --- entry points ---------------------------------------------------------------------------

    def analyze(self, view: ArtifactView) -> None:
        """Analyse one top-level file and everything nested inside it."""
        budget = Budget(self.ctx.policy.limits.archive, view.size)
        try:
            self._analyze(view, 0, budget, top=True)
        except LimitExceeded as exc:
            self.ctx.recorder.fail(
                f"archive.limit.{exc.limit}",
                Subject.of_artifact(view.ref),
                tool=TOOL,
                detail={
                    "stoppedIn": (exc.where or view.ref).display,
                    "expandedBytes": budget.expanded,
                    "members": budget.members,
                },
            )

    def record(
        self, ref: ArtifactRef, entry_type: EntryType, link_target: str | None = None
    ) -> None:
        """Record something that is not a regular file (directory, link, special file)."""
        self.artifacts.append(Artifact(ref, entry_type, link_target=link_target))

    # --- one artifact ---------------------------------------------------------------------------

    def _analyze(
        self,
        view: ArtifactView,
        depth: int,
        budget: Budget,
        *,
        top: bool = False,
        mode: int | None = None,
    ) -> None:
        recorder = self.ctx.recorder
        subject = Subject.of_artifact(view.ref)
        found: list[tuple[int, str]] = []
        tools: list[ToolRef] = []
        metadata: dict[str, object] = {}
        media_type: str | None = None
        for handler in self.handlers:
            tool = ToolRef(handler.name, handler.version)
            try:
                detection = handler.detect(view)
                if detection is None:
                    continue
                inspection = handler.inspect(view, self.ctx)
            except Exception as exc:  # a handler bug must never hide the artifact itself
                recorder.error(
                    "inventory.handler.error",
                    subject,
                    tool=tool,
                    error=f"{type(exc).__name__}: {exc}",
                )
                continue
            tools.append(tool)
            if inspection.kind != UNCLASSIFIED:
                found.append((detection.confidence, inspection.kind))
            metadata.update(inspection.metadata)
            media_type = media_type or inspection.media_type
            self.claims.extend(inspection.claims)
            self.components.extend(inspection.components)
            for finding in inspection.findings:
                recorder.record(finding)

        fmt = detect_format(view.head(_HEAD))
        kinds = [kind for _, kind in sorted(found, key=lambda item: -item[0])]
        if fmt:
            kinds.insert(0, f"archive.{fmt}")
        self.artifacts.append(
            Artifact(
                ref=view.ref,
                entry_type=EntryType.FILE,
                size=view.size,
                kinds=tuple(dict.fromkeys(kinds)) or (UNCLASSIFIED,),
                hashes={"sha256": view.sha256} if view.sha256 else {},
                mode=mode,
                media_type=media_type,
                handlers=tuple(tools),
                metadata={key: jsonable(value) for key, value in metadata.items()},
            )
        )
        if top:
            if kinds:
                recorder.passed("inventory.artifact.unclassified")
            else:
                recorder.fail("inventory.artifact.unclassified", subject, tool=TOOL)
        if fmt:
            self._archive(view, fmt, depth, budget)

    # --- archives -------------------------------------------------------------------------------

    def _archive(self, view: ArtifactView, fmt: str, depth: int, budget: Budget) -> None:
        recorder = self.ctx.recorder
        subject = Subject.of_artifact(view.ref)
        if fmt in UNSUPPORTED:
            recorder.not_assessed(
                ARCHIVE_MEMBER_RULES,
                subject,
                tool=TOOL,
                reason=f"{fmt} archives cannot be opened; contents were not inspected",
            )
            return
        max_depth = self.ctx.policy.limits.archive.max_depth
        if depth >= max_depth:
            recorder.fail("archive.limit.depth", subject, tool=TOOL, detail={"maxDepth": max_depth})
            return
        try:
            with view.open() as stream:
                if fmt in COMPRESSION:
                    self._compressed(view, fmt, stream, depth, budget)
                else:
                    self._container(view, fmt, stream, depth, budget)
        except LimitExceeded as exc:
            exc.where = exc.where or view.ref
            raise
        except ARCHIVE_ERRORS as exc:
            recorder.fail(
                "archive.format.unreadable",
                subject,
                tool=TOOL,
                detail={"error": f"{type(exc).__name__}: {exc}"},
            )

    def _compressed(
        self, view: ArtifactView, fmt: str, stream: IO[bytes], depth: int, budget: Budget
    ) -> None:
        """A gzip/bzip2/xz stream: a tar inside is read in place, anything else is one member."""
        scratch = self._scratch_file()
        try:
            with scratch.open("wb") as sink:
                inner = hash_stream(decompress(fmt, stream), sink=sink, on_bytes=budget.consume)
            with scratch.open("rb") as expanded:
                is_tar = detect_format(expanded.read(_HEAD)) == "tar"
                if is_tar:
                    expanded.seek(0)
                    self._container(view, "tar", expanded, depth, budget)
            if not is_tar:
                ref = view.ref.child(_inner_name(view.ref))
                self._analyze(FileView(ref, scratch, inner.size, inner.sha256), depth + 1, budget)
        finally:
            scratch.unlink(missing_ok=True)

    def _container(
        self, view: ArtifactView, fmt: str, stream: IO[bytes], depth: int, budget: Budget
    ) -> None:
        recorder = self.ctx.recorder
        seen: set[str] = set()
        failed: Counter[str] = Counter()
        total = 0
        top_level: set[str] = set()
        # Decided once the whole archive is seen: whether it is a root filesystem.
        deferred: list[tuple[str, ArtifactRef, dict[str, str]]] = []

        def fail(rule: str, ref: ArtifactRef, **detail: str) -> None:
            failed[rule] += 1
            recorder.fail(rule, Subject.of_artifact(ref), tool=TOOL, detail=dict(detail))

        for member in members(fmt, stream):
            budget.member()
            name, issue = check_member_name(member.name)
            if not name:
                continue  # the archive's own root directory
            total += 1
            top_level.add(name.split("/", 1)[0])
            ref = view.ref.child(name, unsafe=issue is not None)
            if issue is NameIssue.TRAVERSAL:
                fail("archive.member.path-traversal", ref, name=name)
            elif issue is NameIssue.UNSAFE:
                fail("archive.member.unsafe-name", ref, name=name)
            if name in seen:
                fail("archive.member.duplicate", ref, name=name)
                continue
            seen.add(name)

            kind = member.entry_type
            if kind is EntryType.DIRECTORY:
                self.artifacts.append(Artifact(ref, kind, mode=member.mode))
            elif kind in (EntryType.SYMLINK, EntryType.HARDLINK):
                target = member.link_target or ""
                if link_escapes(member.name, target, hard=kind is EntryType.HARDLINK):
                    deferred.append(("archive.member.link-escape", ref, {"target": target}))
                self.artifacts.append(Artifact(ref, kind, link_target=target, mode=member.mode))
            elif kind is EntryType.OTHER:
                fail("archive.member.special-file", ref)
                self.artifacts.append(Artifact(ref, kind, mode=member.mode))
            elif member.encrypted or member.open is None:
                fail("archive.member.encrypted", ref)
                self.artifacts.append(Artifact(ref, kind, size=member.size, mode=member.mode))
            else:
                if member.mode is not None and member.mode & 0o6000:
                    deferred.append(("archive.member.setuid", ref, {"mode": oct(member.mode)}))
                self._member(ref, member, depth, budget)

        # In a root filesystem (an image layer, a rootfs tarball) a link target resolves inside
        # that filesystem, so it cannot escape it, and setuid binaries such as passwd are normal.
        rootfs = len(top_level & _ROOTFS_DIRS) >= 3
        for rule, ref, detail in deferred:
            if rootfs and rule == "archive.member.link-escape":
                continue
            failed[rule] += 1
            recorder.fail(
                rule,
                Subject.of_artifact(ref),
                tool=TOOL,
                detail=detail | ({"context": "root filesystem"} if rootfs else {}),
                severity=Severity.LOW if rootfs else None,
            )
        for rule in ARCHIVE_MEMBER_RULES:
            recorder.passed(rule, total - failed[rule])

    def _member(self, ref: ArtifactRef, member: Member, depth: int, budget: Budget) -> None:
        """Hash one member's bytes; keep a scratch copy only if something will read it again."""
        assert member.open is not None  # noqa: S101
        scratch: Path | None = None
        try:
            with member.open() as raw:
                head = raw.read(_HEAD)
                source = _Prefixed(head, raw)
                if detect_format(head) is not None or self._recognised(ref, head):
                    scratch = self._scratch_file()
                    with scratch.open("wb") as sink:
                        content = hash_stream(source, sink=sink, on_bytes=budget.consume)
                else:
                    content = hash_stream(source, on_bytes=budget.consume)
            view: ArtifactView
            if scratch is not None:
                view = FileView(ref, scratch, content.size, content.sha256)
            else:
                view = HeadView(ref, head, content.size, content.sha256)
            self._analyze(view, depth + 1, budget, mode=member.mode)
        finally:
            if scratch is not None:
                scratch.unlink(missing_ok=True)

    def _recognised(self, ref: ArtifactRef, head: bytes) -> bool:
        probe = HeadView(ref, head, len(head), None)
        return any(h.detect(probe) for h in self.handlers if UNCLASSIFIED not in h.kinds)

    def _scratch_file(self) -> Path:
        self._scratch += 1
        return self._workdir / f"{self._scratch:08d}.bin"


def _inner_name(ref: ArtifactRef) -> str:
    """Name for the single stream inside ``x.gz``: ``x``, or ``data`` if that is not usable."""
    if ref.unsafe:
        return "data"
    name = posixpath.basename((ref.path, *ref.member)[-1])
    for suffix in _SUFFIXES:
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return "data"
