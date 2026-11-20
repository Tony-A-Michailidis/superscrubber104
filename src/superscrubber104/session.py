"""One run of pack or verify: wires up policy, rules and recorder, and ends in an assessment."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from superscrubber104.analyzer import TOOL
from superscrubber104.catalog import builtin_registry
from superscrubber104.core.controls import ControlMapping
from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import (
    ApprovalRecord,
    Assessment,
    Decision,
    Finding,
    PluginStatus,
    Stage,
    Verdict,
    summarize,
)
from superscrubber104.core.policy import Policy, evaluate
from superscrubber104.core.rules import FindingFactory, Recorder, RuleRegistry

EXIT_OK = 0
EXIT_BLOCKED = 1  # a policy blocker stands, or approvals are still required
EXIT_USAGE = 2
EXIT_REFUSED = 3  # integrity/authenticity failed, or a non-overridable policy block

ApprovalCounter = Callable[
    [Sequence[Finding], Sequence[Decision]], tuple[set[str], tuple[ApprovalRecord, ...]]
]


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass(frozen=True, slots=True)
class Session:
    registry: RuleRegistry
    ctx: Context

    @classmethod
    def start(cls, policy: Policy, now: datetime, corpora: tuple[str, ...] = ()) -> "Session":
        catalog = policy.catalog()
        registry = builtin_registry(catalog)
        factory = FindingFactory(registry, ControlMapping(catalog, policy.control_overrides))
        ctx = Context(policy=policy, recorder=Recorder(factory), now=now, corpora=corpora)
        return cls(registry, ctx)

    def finish(
        self,
        stage: Stage,
        *,
        manifest_digest: str | None,
        content_hashes: Mapping[str, str],
        approvals: ApprovalCounter | None = None,
        plugins: tuple[PluginStatus, ...] = (),
    ) -> Assessment:
        """Decide every finding and close the run.

        ``approvals`` is given the findings and decisions and returns the ids of findings
        whose approval quorum is met, plus a record of every approval it looked at.
        """
        recorder, policy = self.ctx.recorder, self.ctx.policy
        findings = recorder.findings
        decisions = evaluate(
            policy,
            self.registry,
            findings,
            today=self.ctx.now.date(),
            content_hashes=content_hashes,
        )
        approved: set[str] = set()
        records: tuple[ApprovalRecord, ...] = ()
        if approvals is not None:
            approved, records = approvals(findings, decisions)
        return Assessment(
            tool=TOOL,
            stage=stage,
            started_at=self.ctx.now,
            finished_at=max(utc_now(), self.ctx.now),
            policy_digest=policy.digest,
            manifest_digest=manifest_digest,
            summary=summarize(findings, decisions, approved),
            plugins=plugins,
            coverage=recorder.coverage(),
            findings=findings,
            decisions=decisions,
            approvals=records,
        )


def exit_code(assessment: Assessment) -> int:
    if assessment.refused:
        return EXIT_REFUSED
    if assessment.summary.verdict is not Verdict.PASSED:
        return EXIT_BLOCKED
    return EXIT_OK
