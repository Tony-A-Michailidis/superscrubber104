"""Checks on the inventory itself: paths, sizes and conformance to the transfer request."""

from collections import defaultdict
from collections.abc import Sequence

from superscrubber104.analyzer import TOOL
from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Entry, EntryType, Subject
from superscrubber104.core.paths import link_escapes
from superscrubber104.core.request import TransferRequest


def check_paths(entries: Sequence[Entry], ctx: Context) -> None:
    recorder, limits = ctx.recorder, ctx.policy.limits

    folded: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        folded[entry.path.casefold()].append(entry.path)
    collisions = [sorted(paths) for paths in folded.values() if len(paths) > 1]
    for paths in collisions:
        recorder.fail(
            "path.case-collision", Subject.of_path(paths[0]), tool=TOOL, detail={"paths": [*paths]}
        )
    recorder.passed("path.case-collision", len(folded) - len(collisions))

    for entry in entries:
        subject = Subject.of_path(entry.path)
        if len(entry.path) > limits.max_path_length:
            recorder.fail(
                "path.length.exceeded",
                subject,
                tool=TOOL,
                detail={"length": len(entry.path), "limit": limits.max_path_length},
            )
        else:
            recorder.passed("path.length.exceeded")
        if entry.size > limits.max_artifact_bytes:
            recorder.fail(
                "size.artifact.exceeded",
                subject,
                tool=TOOL,
                detail={"size": entry.size, "limit": limits.max_artifact_bytes},
            )
        else:
            recorder.passed("size.artifact.exceeded")
        if entry.entry_type is EntryType.SYMLINK:
            target = entry.link_target or ""
            recorder.fail("path.link.symlink", subject, tool=TOOL, detail={"target": target})
            if link_escapes(entry.path, target, hard=False):
                recorder.fail("path.link.escapes", subject, tool=TOOL, detail={"target": target})
        elif entry.entry_type is EntryType.OTHER:
            recorder.fail("path.special-file", subject, tool=TOOL)


def check_request(request: TransferRequest | None, entries: Sequence[Entry], ctx: Context) -> None:
    """Report content the request does not declare, and declared content that is absent.

    Directories are not checked on their own; they are covered by what they contain.
    """
    recorder = ctx.recorder
    rules = ("request.artifact.undeclared", "request.content.missing")
    if request is None:
        recorder.not_assessed(
            rules, Subject.request(), tool=TOOL, reason="the bundle has no transfer request"
        )
        return

    present: set[str] = set()
    for entry in entries:
        if entry.entry_type is EntryType.DIRECTORY:
            continue
        declared = request.entries_for(entry.path)
        present.update(e.name for e in declared)
        if declared or request.allow_undeclared:
            recorder.passed("request.artifact.undeclared")
        else:
            recorder.fail("request.artifact.undeclared", Subject.of_path(entry.path), tool=TOOL)

    for content in request.contents:
        if content.name in present:
            recorder.passed("request.content.missing")
        else:
            recorder.fail(
                "request.content.missing",
                Subject.request(),
                tool=TOOL,
                detail={"content": content.name, "paths": [*content.paths]},
                discriminator=content.name,
            )
