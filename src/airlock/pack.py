"""``airlock pack``: inventory, inspect and sign a delivery into a bundle."""

import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from airlock import bundle as layout
from airlock.analyzer import TOOL, Analyzer
from airlock.checks.inventory import check_paths, check_request
from airlock.checks.transfer import check_policy
from airlock.core import chainlog
from airlock.core.canonical import canonical_bytes, sha256_digest
from airlock.core.errors import ConfigError
from airlock.core.interfaces import Handler
from airlock.core.model import (
    Analysis,
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
from airlock.core.policy import Policy
from airlock.core.request import TransferRequest, load_request
from airlock.core.signing import Signer, sign_envelope
from airlock.handlers.generic import GenericHandler
from airlock.hashing import CHUNK_SIZE, hash_stream
from airlock.session import Session, utc_now
from airlock.walker import FileView, plan_inputs, scan


@dataclass(frozen=True, slots=True)
class PackResult:
    bundle: Path
    assessment: Assessment
    manifest_digest: str
    signed: bool  # False when blocking findings stopped the bundle from being signed


def default_handlers() -> tuple[Handler, ...]:
    """Handlers in dispatch order. The generic handler goes last and accepts everything."""
    return (GenericHandler(),)


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
) -> PackResult:
    """Build a bundle from ``inputs`` in ``output``.

    The bundle is signed unless a finding is decided ``block``: then everything is still written,
    so the findings can be reviewed, but there is no statement and nothing to transfer.
    """
    now = now or utc_now()
    request: TransferRequest | None = load_request(request_path) if request_path else None
    planned = plan_inputs(inputs)
    _prepare_output(output, inputs)
    session = Session.start(policy, now)
    ctx, recorder = session.ctx, session.ctx.recorder

    payload = output / layout.PAYLOAD
    payload.mkdir()
    entries: list[Entry] = []
    files: dict[str, FileView] = {}

    with tempfile.TemporaryDirectory(prefix="airlock-") as scratch:
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
                    with source.location.open("rb") as stream, target.open("xb") as sink:
                        content = hash_stream(stream, sink=sink, chunk_size=chunk_size)
                    entries.append(
                        Entry(
                            path=source.path,
                            entry_type=EntryType.FILE,
                            size=content.size,
                            hashes={"sha256": content.sha256},
                            chunks=content.chunks,
                        )
                    )
                    files[source.path] = FileView(
                        ref, target, content.size, content.sha256, files.get
                    )
                    continue
                if source.entry_type is EntryType.DIRECTORY:
                    target.mkdir()
                entries.append(
                    Entry(source.path, source.entry_type, link_target=source.link_target)
                )
                analyzer.record(ref, source.entry_type, source.link_target)

        for view in files.values():
            analyzer.analyze(view)

    check_paths(entries, ctx)
    check_request(request, entries, ctx)
    check_policy(ctx)

    manifest = Manifest.create(entries, chunk_size=chunk_size)
    subjects = {layout.MANIFEST: layout.write(output / layout.MANIFEST, manifest)}
    manifest_digest = sha256_digest(subjects[layout.MANIFEST])

    analysis = Analysis.create(TOOL, analyzer.artifacts, components=analyzer.components)
    subjects[layout.ANALYSIS] = layout.write(output / layout.ANALYSIS, analysis)

    assessment = session.finish(
        Stage.PACK,
        manifest_digest=manifest_digest,
        content_hashes={e.path: e.hashes["sha256"] for e in entries if e.sha256},
    )
    subjects[layout.ASSESSMENT] = layout.write(output / layout.ASSESSMENT, assessment)

    if request_path is not None:
        subjects[layout.REQUEST] = request_path.read_bytes()
        (output / layout.REQUEST).write_bytes(subjects[layout.REQUEST])

    layout.write(output / layout.DESCRIPTOR, BundleDescriptor())
    signed = assessment.summary.verdict is not Verdict.BLOCKED
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
