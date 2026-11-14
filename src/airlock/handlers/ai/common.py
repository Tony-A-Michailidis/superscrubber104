"""Helpers shared by the AI handlers."""

import re
from collections.abc import Mapping

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context
from airlock.core.model import ArtifactRef, Subject, ToolRef, UnitClaim, UnitKind
from airlock.handlers.ai.templates import inspect_template
from airlock.handlers.common import (
    TooLarge,
    make_claim,
    name_of,
    parent_of,
    read_bytes,
    read_json,
    sibling,
)

TOOL = ToolRef("airlock.ai", __version__)

__all__ = [
    "SHARD",
    "TOOL",
    "TooLarge",
    "check_template",
    "claim",
    "malformed",
    "name_of",
    "parent_of",
    "read_bytes",
    "read_json",
    "sibling",
    "too_large",
]

# model-00001-of-00004.safetensors, model-00002-of-00003.gguf
SHARD = re.compile(r"^(?P<prefix>.+)-(?P<index>\d{5})-of-(?P<total>\d{5})\.(?P<ext>[A-Za-z0-9_]+)$")


def claim(
    view: ArtifactView,
    role: str,
    facts: Mapping[str, object] | None = None,
    *,
    root: ArtifactRef | None = None,
) -> UnitClaim:
    """A claim on the model package rooted at ``root`` (default: the file's directory)."""
    return make_claim(view, UnitKind.MODEL_PACKAGE, role, facts, root=root)


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
