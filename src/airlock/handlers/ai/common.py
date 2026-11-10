"""Helpers shared by the AI handlers."""

import json
import posixpath
import re
from collections.abc import Mapping
from typing import Any

from airlock import __version__
from airlock.core.canonical import JSON, jsonable
from airlock.core.interfaces import ArtifactView, Context
from airlock.core.model import ArtifactRef, Subject, ToolRef, UnitClaim, UnitKind
from airlock.handlers.ai.templates import inspect_template

TOOL = ToolRef("airlock.ai", __version__)

# model-00001-of-00004.safetensors, model-00002-of-00003.gguf
SHARD = re.compile(r"^(?P<prefix>.+)-(?P<index>\d{5})-of-(?P<total>\d{5})\.(?P<ext>[A-Za-z0-9_]+)$")


class TooLarge(ValueError):
    pass


def name_of(ref: ArtifactRef) -> str:
    return posixpath.basename((ref.path, *ref.member)[-1])


def parent_of(ref: ArtifactRef) -> ArtifactRef:
    """The directory an artifact sits in, as a unit root.

    ``ArtifactRef(".")`` stands for the bundle root; for a member at the top of an archive it is
    the archive itself.
    """
    if ref.member:
        directory = posixpath.dirname(ref.member[-1])
        if directory:
            return ArtifactRef(ref.path, (*ref.member[:-1], directory), unsafe=ref.unsafe)
        return ArtifactRef(ref.path, ref.member[:-1], unsafe=ref.unsafe)
    directory = posixpath.dirname(ref.path)
    return ArtifactRef(directory or ".", unsafe=ref.unsafe)


def sibling(ref: ArtifactRef, name: str) -> ArtifactRef:
    """Another file in the same directory (for naming expected shards that may be missing)."""
    if ref.member:
        directory = posixpath.dirname(ref.member[-1])
        member = posixpath.join(directory, name) if directory else name
        return ArtifactRef(ref.path, (*ref.member[:-1], member), unsafe=ref.unsafe)
    return ArtifactRef(posixpath.join(posixpath.dirname(ref.path), name), unsafe=ref.unsafe)


def read_bytes(view: ArtifactView, limit: int) -> bytes:
    if view.size > limit:
        raise TooLarge(f"{view.size} bytes is more than the {limit}-byte limit for this file")
    with view.open() as stream:
        return stream.read(limit + 1)


def _constant(value: str) -> str:
    return value  # NaN and Infinity stay as their names; canonical JSON has no floats


def read_json(view: ArtifactView, limit: int = 64 << 20) -> Any:
    """Parse a JSON file of bounded size. Raises TooLarge or ValueError."""
    raw = read_bytes(view, limit)
    return json.loads(raw.decode("utf-8-sig"), parse_constant=_constant)


def claim(
    view: ArtifactView,
    role: str,
    facts: Mapping[str, object] | None = None,
    *,
    root: ArtifactRef | None = None,
    kind: UnitKind = UnitKind.MODEL_PACKAGE,
) -> UnitClaim:
    return UnitClaim(
        kind=kind,
        root=root or parent_of(view.ref),
        role=role,
        artifact=view.ref,
        sha256=view.sha256,
        facts={key: _fact(value) for key, value in (facts or {}).items()},
    )


def _fact(value: object) -> JSON:
    return jsonable(value)


def check_template(ctx: Context, view: ArtifactView, text: str, locator: str) -> dict[str, object]:
    """Inspect one chat template, record findings, and return its summary for unit facts."""
    report = inspect_template(text)
    subject = Subject.of_artifact(view.ref, locator=locator)
    if report.suspicious:
        ctx.recorder.fail(
            "model.template.suspicious",
            subject,
            tool=TOOL,
            detail={"constructs": [{"reason": r, "excerpt": e} for r, e in report.suspicious]},
        )
    else:
        ctx.recorder.passed("model.template.suspicious")
    if report.invisible:
        ctx.recorder.fail(
            "model.template.hidden-characters",
            subject,
            tool=TOOL,
            detail={"characters": [*report.invisible]},
        )
    else:
        ctx.recorder.passed("model.template.hidden-characters")
    return {
        "source": f"{name_of(view.ref)}#{locator}",
        "sha256": report.sha256,
        "length": report.length,
    }


def malformed(ctx: Context, view: ArtifactView, fmt: str, error: object) -> None:
    ctx.recorder.fail(
        "model.weights.malformed",
        Subject.of_artifact(view.ref),
        tool=TOOL,
        detail={"format": fmt, "error": str(error)},
    )


def too_large(ctx: Context, view: ArtifactView, rules: tuple[str, ...], error: object) -> None:
    ctx.recorder.not_assessed(rules, Subject.of_artifact(view.ref), tool=TOOL, reason=str(error))
