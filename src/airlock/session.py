"""One run of pack or verify: wires up policy, rules and recorder, and ends in an assessment."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from airlock.analyzer import TOOL
from airlock.catalog import builtin_registry
from airlock.core.controls import ControlMapping
from airlock.core.interfaces import Context
from airlock.core.model import Assessment, Stage, Verdict, summarize
from airlock.core.policy import Policy, evaluate
from airlock.core.rules import FindingFactory, Recorder, RuleRegistry

EXIT_OK = 0
EXIT_BLOCKED = 1  # blocking findings, or approvals still required
EXIT_USAGE = 2
EXIT_INTEGRITY = 3  # tampering or a broken trust chain: not a matter of judgement


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass(frozen=True, slots=True)
class Session:
    registry: RuleRegistry
    ctx: Context

    @classmethod
    def start(cls, policy: Policy, now: datetime) -> "Session":
        catalog = policy.catalog()
        registry = builtin_registry(catalog)
        factory = FindingFactory(registry, ControlMapping(catalog, policy.control_overrides))
        return cls(registry, Context(policy=policy, recorder=Recorder(factory), now=now))

    def finish(
        self,
        stage: Stage,
        *,
        manifest_digest: str | None,
        content_hashes: Mapping[str, str],
    ) -> Assessment:
        recorder, policy = self.ctx.recorder, self.ctx.policy
        findings = recorder.findings
        decisions = evaluate(
            policy,
            self.registry,
            findings,
            today=self.ctx.now.date(),
            content_hashes=content_hashes,
        )
        return Assessment(
            tool=TOOL,
            stage=stage,
            started_at=self.ctx.now,
            finished_at=max(utc_now(), self.ctx.now),
            policy_digest=policy.digest,
            manifest_digest=manifest_digest,
            summary=summarize(findings, decisions),
            coverage=recorder.coverage(),
            findings=findings,
            decisions=decisions,
        )


def exit_code(assessment: Assessment) -> int:
    if assessment.integrity_failed:
        return EXIT_INTEGRITY
    if assessment.summary.verdict is not Verdict.PASSED:
        return EXIT_BLOCKED
    return EXIT_OK
