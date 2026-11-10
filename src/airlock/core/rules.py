"""Rule registry and the finding factory.

Every check is declared as a ``RuleSpec`` before it can produce findings, so no check ships without
a severity, a rationale and a control mapping, and the registry can be rendered straight into docs.
"""

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass

from airlock.core.canonical import JSON, digest
from airlock.core.controls import ControlCatalog, ControlMapping
from airlock.core.errors import RuleError
from airlock.core.model import Finding, Result, Severity, Subject, ToolRef
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


class FindingFactory:
    """The only way checks create findings: looks up the rule and applies control overrides."""

    def __init__(self, registry: RuleRegistry, mapping: ControlMapping | None = None) -> None:
        self.registry = registry
        self.mapping = mapping or ControlMapping(registry.catalog)

    def __call__(
        self,
        rule: str,
        subject: Subject,
        result: Result,
        *,
        tool: ToolRef,
        detail: Mapping[str, JSON] | None = None,
        title: str | None = None,
        severity: Severity | None = None,
        discriminator: str = "",
        reason: str | None = None,
    ) -> Finding:
        """Create a finding.

        ``discriminator`` separates several findings of one rule on one subject (e.g. one per
        dangerous import). ``reason`` is required for, and only allowed with, NOT_ASSESSED.
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
            controls=self.mapping.controls_for(rule, spec.controls),
            tool=tool,
            detail=dict(detail or {}),
            not_assessed_reason=reason,
        )

    def not_assessed(
        self, rules: Iterable[str], subject: Subject, *, tool: ToolRef, reason: str
    ) -> list[Finding]:
        """NOT_ASSESSED findings for every rule a check could not run."""
        return [
            self(rule, subject, Result.NOT_ASSESSED, tool=tool, reason=reason) for rule in rules
        ]
