"""Rule registry, the finding factory and the per-run recorder.

Every check is declared as a ``RuleSpec`` before it can produce findings, so no check ships without
a severity, a rationale and a control mapping, and the registry can be rendered straight into docs.
"""

import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass

from airlock.core.canonical import JSON, digest
from airlock.core.controls import ControlCatalog, ControlMapping
from airlock.core.errors import RuleError
from airlock.core.model import (
    Coverage,
    Finding,
    Result,
    Severity,
    Subject,
    ToolRef,
)
from airlock.core.serde import to_data

_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$")


@dataclass(frozen=True, slots=True)
class RuleSpec:
    id: str  # "<domain>.<subject>.<condition>", e.g. "model.pickle.dangerous-import"
    version: str
    title: str
    severity: Severity
    controls: tuple[str, ...]
    rationale: str
    remediation: str = ""
    # Integrity and authenticity checks: a FAIL or ERROR is always ``block`` and can never be
    # waived, lowered by policy or overridden by approvals. If these could be waived, the
    # airlock would not be a control.
    final: bool = False
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _RULE_ID.match(self.id):
            raise RuleError(f"invalid rule id {self.id!r}: use lowercase dotted segments")
        if not self.controls:
            raise RuleError(f"rule {self.id!r} must map to at least one control")


class RuleRegistry:
    def __init__(self, catalog: ControlCatalog) -> None:
        self.catalog = catalog
        self._rules: dict[str, RuleSpec] = {}

    def register(self, *specs: RuleSpec) -> None:
        for spec in specs:
            if spec.id in self._rules:
                raise RuleError(f"rule {spec.id!r} is already registered")
            self.catalog.check(spec.controls, f"rule {spec.id!r}")
            self._rules[spec.id] = spec

    def get(self, rule_id: str) -> RuleSpec:
        try:
            return self._rules[rule_id]
        except KeyError:
            raise RuleError(f"unknown rule {rule_id!r}") from None

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __iter__(self) -> Iterator[RuleSpec]:
        return iter(sorted(self._rules.values(), key=lambda r: r.id))

    def __len__(self) -> int:
        return len(self._rules)


def finding_id(rule: str, subject: Subject, discriminator: str) -> str:
    """Deterministic id: the same check on the same subject always gets the same id."""
    return digest([rule, to_data(subject), discriminator]).removeprefix("sha256:")[:16]


def finding_digest(finding: Finding) -> str:
    """Digest of what a finding says. Approvals bind to this, not just to the id.

    Covers the rule and its version, the subject, the result and everything that was found.
    Leaves out the reporting tool's version and presentation (title, controls), so an approval
    given on one side still matches the same finding recomputed by a newer tool on the other.
    """
    return digest(
        [
            finding.id,
            finding.rule,
            finding.rule_version,
            finding.result.value,
            finding.severity.value,
            to_data(finding.subject),
            dict(finding.detail),
            dict(finding.attributes),
        ]
    )


class FindingFactory:
    """The only way checks create findings: looks up the rule and applies control overrides."""

    def __init__(self, registry: RuleRegistry, mapping: ControlMapping | None = None) -> None:
        self.registry = registry
        self.mapping = mapping or ControlMapping(registry.catalog)

    def controls_for(self, rule: str) -> tuple[str, ...]:
        return self.mapping.controls_for(rule, self.registry.get(rule).controls)

    def __call__(
        self,
        rule: str,
        subject: Subject,
        result: Result,
        *,
        tool: ToolRef,
        detail: Mapping[str, JSON] | None = None,
        attributes: Mapping[str, str] | None = None,
        title: str | None = None,
        severity: Severity | None = None,
        discriminator: str = "",
        reason: str | None = None,
    ) -> Finding:
        """Create a finding.

        ``discriminator`` separates several findings of one rule on one subject (e.g. one per
        dangerous import). ``attributes`` are facets that policy ``where`` clauses can select on.
        ``reason`` is required for, and only allowed with, NOT_ASSESSED.
        """
        spec = self.registry.get(rule)
        return Finding(
            id=finding_id(rule, subject, discriminator),
            rule=rule,
            rule_version=spec.version,
            result=result,
            severity=severity or spec.severity,
            subject=subject,
            title=title or spec.title,
            controls=self.controls_for(rule),
            tool=tool,
            detail=dict(detail or {}),
            attributes=dict(attributes or {}),
            not_assessed_reason=reason,
        )


class Recorder:
    """Collects the evidence of one run: findings, plus counts of checks that passed.

    A pass is normally a count, not a finding, so a bundle of a million files does not produce a
    million rows. Anything that is not a pass is always an individual finding.
    """

    def __init__(self, factory: FindingFactory) -> None:
        self.factory = factory
        self._findings: dict[str, Finding] = {}
        self._passed: Counter[str] = Counter()

    def record(self, finding: Finding) -> Finding:
        self.factory.registry.get(finding.rule)
        return self._findings.setdefault(finding.id, finding)

    def fail(
        self,
        rule: str,
        subject: Subject,
        *,
        tool: ToolRef,
        detail: Mapping[str, JSON] | None = None,
        attributes: Mapping[str, str] | None = None,
        discriminator: str = "",
    ) -> Finding:
        return self.record(
            self.factory(
                rule,
                subject,
                Result.FAIL,
                tool=tool,
                detail=detail,
                attributes=attributes,
                discriminator=discriminator,
            )
        )

    def not_assessed(
        self, rules: Iterable[str], subject: Subject, *, tool: ToolRef, reason: str
    ) -> None:
        """Record, for each rule, that it could not be checked on this subject."""
        for rule in rules:
            self.record(self.factory(rule, subject, Result.NOT_ASSESSED, tool=tool, reason=reason))

    def error(self, rule: str, subject: Subject, *, tool: ToolRef, error: str) -> Finding:
        return self.record(
            self.factory(rule, subject, Result.ERROR, tool=tool, detail={"error": error})
        )

    def passed(self, rule: str, count: int = 1) -> None:
        self.factory.registry.get(rule)
        self._passed[rule] += count

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(
            sorted(self._findings.values(), key=lambda f: (f.rule, f.subject.display, f.id))
        )

    def coverage(self) -> tuple[Coverage, ...]:
        """One row per registered rule, including rules that never ran."""
        by_result: Counter[tuple[str, Result]] = Counter(
            (f.rule, f.result) for f in self._findings.values()
        )
        return tuple(
            Coverage(
                rule=spec.id,
                rule_version=spec.version,
                controls=self.factory.controls_for(spec.id),
                passed=self._passed[spec.id] + by_result[spec.id, Result.PASS],
                failed=by_result[spec.id, Result.FAIL],
                not_assessed=by_result[spec.id, Result.NOT_ASSESSED],
                errors=by_result[spec.id, Result.ERROR],
            )
            for spec in self.factory.registry
        )
