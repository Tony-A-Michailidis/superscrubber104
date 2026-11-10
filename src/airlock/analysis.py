"""Closing an analysis: assemble units from claims, attach what was verified, check trust."""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace

from airlock.analyzer import TOOL, Analyzer
from airlock.checks.provenance import check_upstream_trust
from airlock.core.interfaces import UnitAssembler
from airlock.core.model import (
    Analysis,
    ArtifactRef,
    Component,
    Subject,
    ToolRef,
    Unit,
    Verification,
)


def finish(analyzer: Analyzer, assemblers: Sequence[UnitAssembler]) -> Analysis:
    ctx = analyzer.ctx
    units: list[Unit] = []
    components: list[Component] = list(analyzer.components)
    verified: dict[ArtifactRef, list[Verification]] = defaultdict(list)
    for assembler in assemblers:
        claims = [c for c in analyzer.claims if c.kind is assembler.kind]
        if not claims:
            continue
        try:
            for assembly in assembler.assemble(claims, ctx):
                units.append(assembly.unit)
                components.extend(assembly.components)
                for ref, verifications in assembly.verifications.items():
                    verified[ref].extend(verifications)
        except Exception as exc:  # an assembler bug must not lose the rest of the evidence
            ctx.recorder.error(
                "inventory.handler.error",
                Subject.bundle(),
                tool=ToolRef(assembler.name, assembler.version),
                error=f"{type(exc).__name__}: {exc}",
            )
    artifacts = [
        replace(a, verifications=(*a.verifications, *verified[a.ref])) if a.ref in verified else a
        for a in analyzer.artifacts
    ]
    check_upstream_trust(artifacts, ctx)
    return Analysis.create(TOOL, artifacts, units, components)
