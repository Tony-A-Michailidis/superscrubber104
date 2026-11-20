"""``superscrubber104 pack``: inventory, inspect and sign a delivery into a bundle."""

import json
import os
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from superscrubber104 import bundle as layout
from superscrubber104 import volumes
from superscrubber104.analysis import finish
from superscrubber104.analyzer import TOOL, Analyzer
from superscrubber104.checks.inventory import check_paths, check_request
from superscrubber104.checks.transfer import check_policy
from superscrubber104.checks.units import check_request_units
from superscrubber104.core import chainlog
from superscrubber104.core.canonical import canonical_bytes, sha256_digest
from superscrubber104.core.errors import ConfigError
from superscrubber104.core.interfaces import Handler
from superscrubber104.core.model import (
    ArtifactRef,
    Assessment,
    BundleDescriptor,
    Entry,
    EntryType,
    Manifest,
    Provenance,
    Stage,
    Subject,
    Verdict,
)
from superscrubber104.core.policy import Policy
from superscrubber104.core.request import TransferRequest, load_request
from superscrubber104.core.serde import from_data
from superscrubber104.core.signing import Signer, sign_envelope
from superscrubber104.handlers import default_handlers
from superscrubber104.hashing import CHUNK_SIZE, FileDigest, hash_stream
from superscrubber104.scanners import run_scanners, targets
from superscrubber104.session import Session, utc_now
from superscrubber104.units import default_assemblers
from superscrubber104.volumes import VolumeWriter
from superscrubber104.walker import FileView, Source, plan_inputs, scan


@dataclass(frozen=True, slots=True)
class PackResult:
    bundle: Path
    assessment: Assessment
    manifest_digest: str
    signed: bool  # False when blocking findings stopped the bundle from being signed


def _load_base(path: Path) -> tuple[str, dict[str, Entry]]:
    """The base snapshot of a delta: its manifest digest and its files by path."""
    manifest_path = path / layout.MANIFEST if path.is_dir() else path
    try:
        data = manifest_path.read_bytes()
        base = from_data(Manifest, json.loads(data))
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"cannot read the base manifest {manifest_path}: {exc}") from exc
    files = {e.path: e for e in base.entries if e.entry_type is EntryType.FILE}
    return sha256_digest(data), files


def _store(
    source: Source,
    target: Path,
    writer: VolumeWriter | None,
    base: dict[str, Entry],
    chunk_size: int,
    link: bool,
) -> tuple[FileDigest, Path, bool]:
    """Put one file in the payload. Returns its digest, where analysis reads it, and whether
    it is carried from the base snapshot (and so not stored at all)."""
    previous = base.get(source.path)
    if previous is not None and previous.size == source.location.stat().st_size:
        with source.location.open("rb") as stream:
            content = hash_stream(stream, chunk_size=chunk_size)
        if content.sha256 == previous.sha256:
            return content, source.location, True
    if writer is not None:
        with source.location.open("rb") as stream:
            size = source.location.stat().st_size
            return writer.write(source.path, stream, size, chunk_size), source.location, False
    if link:
        try:
            os.link(source.location, target)
        except OSError:
            pass  # another filesystem, or links not allowed: copy instead
        else:
            with target.open("rb") as stream:
                return hash_stream(stream, chunk_size=chunk_size), target, False
    with source.location.open("rb") as stream, target.open("xb") as sink:
        return hash_stream(stream, sink=sink, chunk_size=chunk_size), target, False


def _prepare_output(output: Path, inputs: Sequence[Path]) -> None:
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ConfigError(f"output must be a new or empty directory: {output}")
    resolved = output.resolve()
    for path in inputs:
        source = path.resolve()
        if resolved == source or source in resolved.parents:
            raise ConfigError(f"output {output} is inside input {path}; it would pack itself")
    output.mkdir(parents=True, exist_ok=True)


def pack(
    inputs: Sequence[Path],
    output: Path,
    *,
    signer: Signer,
    policy: Policy,
    request_path: Path | None = None,
    handlers: Sequence[Handler] | None = None,
    now: datetime | None = None,
    bundle_id: str | None = None,
    chunk_size: int = CHUNK_SIZE,
    volume_size: int | None = None,
    delta_from: Path | None = None,
    link: bool = False,
) -> PackResult:
    """Build a bundle from ``inputs`` in ``output``.

    The bundle is signed unless it is refused outright (a failure nothing can override, such
    as a file name that cannot be stored). Everything is still written then, so the findings
    can be reviewed, but there is no statement and nothing to transfer. A bundle with policy
    blockers is signed: whether to override them is for approvers and the receiving side.

    ``volume_size`` splits the payload across volumes for removable media
    (``superscrubber104.volumes``). ``delta_from`` names an earlier bundle (or its manifest): files
    unchanged since then are recorded as carried and not copied. ``link`` hard-links files into the
    payload instead of copying them, when the filesystem allows.
    """
    now = now or utc_now()
    request: TransferRequest | None = load_request(request_path) if request_path else None
    planned = plan_inputs(inputs)
    _prepare_output(output, inputs)
    session = Session.start(policy, now, request.corpora if request else ())
    ctx, recorder = session.ctx, session.ctx.recorder

    base_digest, base_entries = _load_base(delta_from) if delta_from else (None, {})
    writer = VolumeWriter(output, volume_size) if volume_size else None
    payload = output / layout.PAYLOAD
    if writer is None:
        payload.mkdir()
    entries: list[Entry] = []
    files: dict[str, FileView] = {}

    with tempfile.TemporaryDirectory(prefix="superscrubber104-") as scratch:
        analyzer = Analyzer(ctx, handlers or default_handlers(), Path(scratch))

        for prefix, location in planned:
            for source in scan(prefix, location):
                if not source.safe:
                    ref = ArtifactRef(source.path, unsafe=True)
                    recorder.fail("path.name.unsafe", Subject.of_artifact(ref), tool=TOOL)
                    analyzer.record(ref, source.entry_type)
                    continue
                recorder.passed("path.name.unsafe")
                ref = ArtifactRef(source.path)
                target = payload / source.path
                if source.entry_type is EntryType.FILE:
                    content, location, carried = _store(
                        source, target, writer, base_entries, chunk_size, link
                    )
                    entries.append(
                        Entry(
                            path=source.path,
                            entry_type=EntryType.FILE,
                            size=content.size,
                            hashes={"sha256": content.sha256},
                            chunks=content.chunks,
                            carried=carried,
                        )
                    )
                    files[source.path] = FileView(
                        ref, location, content.size, content.sha256, files.get
                    )
                    continue
                if source.entry_type is EntryType.DIRECTORY:
                    if writer is None:
                        target.mkdir()
                    else:
                        writer.directory(source.path)
                entries.append(
                    Entry(source.path, source.entry_type, link_target=source.link_target)
                )
                analyzer.record(ref, source.entry_type, source.link_target)

        for view in files.values():
            analyzer.analyze(view)
        analysis = finish(analyzer, default_assemblers())

    plugins = run_scanners(ctx, targets(files.values()), analysis)
    check_paths(entries, ctx)
    check_request(request, entries, ctx)
    check_request_units(request, analysis.units, ctx)
    check_policy(ctx)

    manifest = Manifest.create(entries, chunk_size=chunk_size, base=base_digest)
    subjects = {layout.MANIFEST: layout.write(output / layout.MANIFEST, manifest)}
    if writer is not None:
        subjects[volumes.INDEX] = volumes.write_index(output, writer.finish())
    manifest_digest = sha256_digest(subjects[layout.MANIFEST])

    subjects[layout.ANALYSIS] = layout.write(output / layout.ANALYSIS, analysis)

    assessment = session.finish(
        Stage.PACK,
        manifest_digest=manifest_digest,
        content_hashes={e.path: e.hashes["sha256"] for e in entries if e.sha256},
        plugins=plugins,
    )
    subjects[layout.ASSESSMENT] = layout.write(output / layout.ASSESSMENT, assessment)

    if request_path is not None:
        subjects[layout.REQUEST] = request_path.read_bytes()
        (output / layout.REQUEST).write_bytes(subjects[layout.REQUEST])

    layout.write(output / layout.DESCRIPTOR, BundleDescriptor())
    signed = assessment.summary.verdict is not Verdict.REFUSED
    if signed:
        provenance = Provenance(
            bundle_id=bundle_id or uuid.uuid4().hex,
            created_at=now,
            tool=TOOL,
            policy_digest=policy.digest,
            source=request.source if request else None,
            destination=request.destination if request else None,
            stream=request.stream if request else "default",
            profile=request.profile.value if request else "routine",
            request_id=request.id if request else None,
        )
        statement = layout.build_statement(
            {name: sha256_digest(data).removeprefix("sha256:") for name, data in subjects.items()},
            provenance,
        )
        envelope = canonical_bytes(
            sign_envelope(layout.STATEMENT_PAYLOAD_TYPE, statement, signer).to_data()
        )
        (output / layout.STATEMENT).write_bytes(envelope)
        chainlog.append(
            output / layout.CUSTODY,
            layout.EVENT_PACKED,
            {
                "bundleId": provenance.bundle_id,
                "manifestDigest": manifest_digest,
                "statementDigest": sha256_digest(envelope),
            },
            now=now,
            signer=signer,
        )
    return PackResult(output, assessment, manifest_digest, signed)
