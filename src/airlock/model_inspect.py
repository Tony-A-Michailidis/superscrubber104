"""``airlock model inspect``: the model package record and findings for paths, without packing.

Runs the same handlers, assemblers and checks as pack, in place: nothing is copied and nothing is
signed. Useful on the packing side before a transfer, and on the receiving side on content that
arrived some other way.
"""

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from airlock.analysis import finish
from airlock.analyzer import TOOL, Analyzer
from airlock.checks.transfer import check_policy
from airlock.core.interfaces import Handler
from airlock.core.model import Analysis, ArtifactRef, Assessment, EntryType, Stage, Subject
from airlock.core.policy import Policy
from airlock.handlers import default_handlers
from airlock.hashing import hash_stream
from airlock.scanners import run_scanners, targets
from airlock.session import Session, utc_now
from airlock.units import default_assemblers
from airlock.walker import FileView, plan_inputs, scan


@dataclass(frozen=True, slots=True)
class InspectResult:
    analysis: Analysis
    assessment: Assessment


def inspect_paths(
    inputs: Sequence[Path],
    *,
    policy: Policy,
    now: datetime | None = None,
    handlers: Sequence[Handler] | None = None,
    run_plugins: bool = True,
) -> InspectResult:
    now = now or utc_now()
    planned = plan_inputs(inputs)
    session = Session.start(policy, now)
    ctx = session.ctx
    files: dict[str, FileView] = {}
    with tempfile.TemporaryDirectory(prefix="airlock-") as scratch:
        analyzer = Analyzer(ctx, handlers or default_handlers(), Path(scratch))
        for prefix, location in planned:
            for source in scan(prefix, location):
                if not source.safe:
                    ref = ArtifactRef(source.path, unsafe=True)
                    ctx.recorder.fail("path.name.unsafe", Subject.of_artifact(ref), tool=TOOL)
                    analyzer.record(ref, source.entry_type)
                    continue
                ref = ArtifactRef(source.path)
                if source.entry_type is EntryType.FILE:
                    with source.location.open("rb") as stream:
                        digest = hash_stream(stream)
                    files[source.path] = FileView(
                        ref, source.location, digest.size, digest.sha256, files.get
                    )
                else:
                    analyzer.record(ref, source.entry_type, source.link_target)
        for view in files.values():
            analyzer.analyze(view)
        analysis = finish(analyzer, default_assemblers())
    plugins = run_scanners(ctx, targets(files.values()), analysis) if run_plugins else ()
    check_policy(ctx)
    assessment = session.finish(
        Stage.INSPECT,
        manifest_digest=None,
        content_hashes={path: view.sha256 for path, view in files.items() if view.sha256},
        plugins=plugins,
    )
    return InspectResult(analysis, assessment)
