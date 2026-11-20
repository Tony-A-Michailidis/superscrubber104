"""Shared pieces for the Java, Go, Rust and .NET handlers: claims, sidecar checksums, build hooks.

The claim facts are the contract with ``superscrubber104.units.locked_env``.
"""

import base64
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence

from superscrubber104.core.interfaces import ArtifactView, Context
from superscrubber104.core.model import (
    Component,
    ComponentType,
    Result,
    Subject,
    ToolRef,
    TrustLevel,
    UnitClaim,
    UnitKind,
    Verification,
)
from superscrubber104.handlers.common import full_path, make_claim

_HEX = re.compile(r"^[0-9a-fA-F]+$")


def requirement(
    name: str, version: str, hashes: Iterable[str] = (), *, vendored: bool = False
) -> dict[str, object]:
    return {"name": name, "version": version, "hashes": sorted(set(hashes)), "vendored": vendored}


def lockfile_claim(
    view: ArtifactView,
    kind: UnitKind,
    ecosystem: str,
    fmt: str,
    requirements: Sequence[Mapping[str, object]],
) -> UnitClaim:
    # The lockfile itself is the unit root: a project can hold several (gradle.lockfile and
    # verification-metadata.xml), each its own unit.
    facts = {"ecosystem": ecosystem, "format": fmt, "requirements": list(requirements)}
    return make_claim(view, kind, "lockfile", facts, root=view.ref)


def distribution_claim(
    view: ArtifactView,
    kind: UnitKind,
    ecosystem: str,
    name: str,
    version: str,
    hashes: Iterable[str],
    bom_ref: str | None = None,
) -> UnitClaim:
    facts = {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "hashes": sorted(set(hashes)),
        "bomRef": bom_ref,
    }
    return make_claim(view, kind, "distribution", facts)


def component(view: ArtifactView, name: str, version: str, purl: str, **extra: object) -> Component:
    return Component(
        bom_ref=f"{purl}#{view.sha256 or full_path(view.ref)}"[:300],
        type=ComponentType.LIBRARY,
        name=name,
        version=version,
        purl=purl,
        hashes={"sha256": view.sha256} if view.sha256 else {},
        evidence=(view.ref,),
        **extra,  # type: ignore[arg-type]
    )


def digest_hex(view: ArtifactView, algorithm: str) -> str:
    if algorithm == "sha256" and view.sha256:
        return view.sha256
    digest = hashlib.new(algorithm, usedforsecurity=False)  # sha1 here only names a file
    with view.open() as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def b64_to_hex(value: str) -> str | None:
    try:
        return base64.b64decode(value, validate=True).hex()
    except ValueError:
        return None


def check_sidecar(
    view: ArtifactView,
    ctx: Context,
    tool: ToolRef,
    algorithm: str,
    recorded: str,
    source: str,
    verification_type: str,
) -> Verification | None:
    """Compare a checksum recorded beside the file (hex or base64); final on mismatch."""
    expected = recorded.strip().split()[0].lower() if recorded.strip() else ""
    if expected and not _HEX.match(expected):
        expected = b64_to_hex(recorded.strip()) or ""
    if not expected:
        return None
    actual = digest_hex(view, algorithm)
    if actual != expected:
        ctx.recorder.fail(
            "package.checksum-mismatch",
            Subject.of_artifact(view.ref),
            tool=tool,
            detail={
                "recordedIn": source,
                "algorithm": algorithm,
                "recorded": expected,
                "actual": actual,
            },
        )
        return None
    ctx.recorder.passed("package.checksum-mismatch")
    return Verification(verification_type, TrustLevel.CHECKSUM, Result.PASS, anchor=source)


def build_hooks(view: ArtifactView, ctx: Context, tool: ToolRef, hooks: Sequence[str]) -> None:
    """Code that runs when the package is built or installed: recorded for review."""
    if hooks:
        ctx.recorder.fail(
            "package.build-hooks",
            Subject.of_artifact(view.ref),
            tool=tool,
            detail={"hooks": sorted(set(hooks))},
        )
