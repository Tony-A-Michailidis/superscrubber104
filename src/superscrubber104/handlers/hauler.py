"""Hauler hauls (``haul.tar.zst``, ``haul.tar.gz``, ``haul.tar``), read without Hauler.

A haul is a Hauler store saved as one archive: an OCI image layout holding images, Helm charts
and files, with the signatures, attestations and SBOMs Hauler kept beside them (marked by a
``kind`` annotation such as ``dev.hauler/sigs``).

One streaming pass hashes every member and keeps the small JSON documents. Then:

* **Layout.** The container checks run over the whole layout: every blob must hash to its name and
  every referenced blob be present (both final), and images get the usual image checks.
* **Contents.** Images, charts and files are listed on a ``hauler-haul`` unit, with which of
  them carry signatures, attestations or SBOMs.
* **Signatures.** Hauler verifies cosign signatures when it saves and loads a haul. superscrubber104
  does not verify cosign signatures yet, so when a haul carries them that is recorded as "not
  assessed", never as verified.

Everything inside (chart archives, files, image layers and the models in them) goes through the
ordinary archive walk. Not validated on a real haul: none was published to examine (doc 35).
"""

import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from typing import IO

from superscrubber104 import __version__
from superscrubber104.archive import (
    ARCHIVE_ERRORS,
    ZSTD,
    ZSTD_ADVICE,
    capped,
    decompress,
    detect_format,
)
from superscrubber104.core.canonical import jsonable
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject, ToolRef, UnitClaim, UnitKind
from superscrubber104.core.paths import check_member_name
from superscrubber104.handlers.common import name_of
from superscrubber104.handlers.containers import (
    HAUL_NAME,
    MemoryStore,
    inspect_store,
    report_conflicts,
)

TOOL = ToolRef("superscrubber104.hauler", __version__)
KIND = "hauler.haul"
LAYOUT_RULES = (
    "container.image.incomplete",
    "container.layer.digest-mismatch",
    "package.member.conflicting-copies",
)
SIGNATURE_RULES = ("upstream.signature.invalid", "upstream.signature.untrusted")


@contextmanager
def _open(view: ArtifactView, ctx: Context) -> Iterator[IO[bytes]]:
    """The haul's tar stream: as is, or decompressed within the expansion limit."""
    fmt = detect_format(view.head(512))
    with view.open() as raw:
        if fmt in ("zstd", "gzip"):
            with decompress(fmt, raw) as expanded:
                yield capped(expanded, ctx.policy.limits.archive.allowance(view.size))
        else:
            yield raw


def _read(stream: IO[bytes]) -> MemoryStore:
    store = MemoryStore()
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name, _ = check_member_name(member.name)
            if not name or not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is not None:
                store.add(name, handle)
    return store


class HaulHandler:
    name = "hauler"
    version = "1"
    kinds = frozenset({KIND})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if not HAUL_NAME.match(name_of(artifact.ref)):
            return None
        if detect_format(artifact.head(512)) in ("zstd", "gzip", "tar"):
            return Detection(KIND, 85)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        subject = Subject.of_artifact(artifact.ref)
        if detect_format(artifact.head(512)) == "zstd" and not ZSTD:
            ctx.recorder.not_assessed(LAYOUT_RULES, subject, tool=TOOL, reason=ZSTD_ADVICE)
            return Inspection(kind=KIND, metadata={"hauler": {"readable": False}})
        try:
            with _open(artifact, ctx) as stream:
                store = _read(stream)
        except ARCHIVE_ERRORS as exc:
            ctx.recorder.not_assessed(
                LAYOUT_RULES,
                subject,
                tool=TOOL,
                reason=f"the haul cannot be read: {type(exc).__name__}: {str(exc)[:200]}",
            )
            return Inspection(kind=KIND, metadata={"hauler": {"readable": False}})
        if not (store.exists("index.json") and store.exists("oci-layout")):
            return Inspection(kind="unclassified")  # named like a haul, but not an OCI layout
        report_conflicts(ctx, subject, store.digests, store.conflicts, TOOL)
        try:
            layout = inspect_store(store, ctx, artifact, KIND, root=artifact.ref)
        except (ValueError, KeyError, TypeError, RecursionError) as exc:
            ctx.recorder.not_assessed(
                LAYOUT_RULES,
                subject,
                tool=TOOL,
                reason=f"the haul's image index cannot be read: {str(exc)[:200]}",
            )
            return Inspection(kind=KIND, metadata={"hauler": {"readable": False}})
        container = layout.metadata.get("container")
        container = container if isinstance(container, dict) else {}
        images = [i for i in container.get("images") or [] if isinstance(i, dict)]
        others = [a for a in container.get("artifacts") or [] if isinstance(a, dict)]
        by_kind: dict[str, list[str]] = {}
        for entry in others:
            label = entry.get("title") or entry.get("name") or entry.get("manifestDigest")
            by_kind.setdefault(str(entry.get("kind")), []).append(str(label))
        signed = by_kind.get("signature", []) + by_kind.get("attestation", [])
        if signed:
            ctx.recorder.not_assessed(
                SIGNATURE_RULES,
                subject,
                tool=TOOL,
                reason=f"the haul carries {len(signed)} cosign signatures or attestations; "
                "superscrubber104 does not verify cosign signatures yet (Hauler verifies them when "
                "it "
                "saves and loads a haul)",
            )
        summary: dict[str, object] = {
            "images": [i.get("name") for i in images],
            "charts": by_kind.get("helm-chart", []),
            "files": by_kind.get("file", []),
            "signatures": by_kind.get("signature", []),
            "attestations": by_kind.get("attestation", []),
            "sboms": by_kind.get("sbom", []),
            "other": by_kind.get("artifact", []) + by_kind.get("referrer", []),
            "blobs": len(list(store.blobs())),
            "signaturesVerified": False,
        }
        claim = UnitClaim(
            UnitKind.HAULER_HAUL,
            artifact.ref,
            "haul",
            artifact.ref,
            artifact.sha256,
            {key: jsonable(value) for key, value in summary.items()},
        )
        return Inspection(
            kind=KIND,
            metadata={**layout.metadata, "hauler": summary},
            claims=(claim, *layout.claims),
        )
