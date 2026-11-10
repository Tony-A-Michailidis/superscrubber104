import pytest

from airlock.core.controls import ControlCatalog, ControlMapping, ControlOverride
from airlock.core.errors import RuleError
from airlock.core.model import ArtifactRef, Result, Severity, Subject
from airlock.core.rules import FindingFactory, RuleRegistry, RuleSpec
from tests.core.helpers import RULES, TOOL

SUBJECT = Subject.of_artifact(ArtifactRef("models/x.pt"))


def test_builtin_catalogue(catalog: ControlCatalog) -> None:
    assert catalog.framework == "nist-800-53r5"
    assert "SI-7" in catalog
    assert catalog.get("SR-11").family == "SR"
    assert len(list(catalog)) == 21


def test_registry_rejects_duplicates_and_unknown_controls(catalog: ControlCatalog) -> None:
    registry = RuleRegistry(catalog)
    registry.register(RULES[0])
    with pytest.raises(RuleError, match="already registered"):
        registry.register(RULES[0])
    bogus = RuleSpec("a.b", "1", "t", Severity.LOW, ("XX-99",), "r")
    with pytest.raises(RuleError, match="unknown control"):
        registry.register(bogus)
    with pytest.raises(RuleError, match="unknown rule"):
        registry.get("nope.nope")


@pytest.mark.parametrize("rule_id", ["single", "Upper.case", "a..b", "a.b_c", ".a.b"])
def test_rule_id_format(rule_id: str) -> None:
    with pytest.raises(RuleError):
        RuleSpec(rule_id, "1", "t", Severity.LOW, ("SI-7",), "r")


def test_rule_needs_controls() -> None:
    with pytest.raises(RuleError, match="control"):
        RuleSpec("a.b", "1", "t", Severity.LOW, (), "r")


def test_registry_iterates_sorted(registry: RuleRegistry) -> None:
    ids = [r.id for r in registry]
    assert ids == sorted(ids)
    assert len(registry) == len(RULES)


def test_finding_factory(findings: FindingFactory) -> None:
    f = findings("model.pickle.dangerous-import", SUBJECT, Result.FAIL, tool=TOOL)
    assert f.severity is Severity.CRITICAL
    assert f.controls == ("SI-3", "SR-10")
    assert f.rule_version == "1"
    assert len(f.id) == 16
    again = findings("model.pickle.dangerous-import", SUBJECT, Result.FAIL, tool=TOOL)
    assert again.id == f.id
    other = findings(
        "model.pickle.dangerous-import", SUBJECT, Result.FAIL, tool=TOOL, discriminator="os.system"
    )
    assert other.id != f.id


def test_finding_unknown_rule(findings: FindingFactory) -> None:
    with pytest.raises(RuleError):
        findings("not.registered", SUBJECT, Result.FAIL, tool=TOOL)


def test_not_assessed_needs_reason(findings: FindingFactory) -> None:
    with pytest.raises(ValueError, match="not_assessed_reason"):
        findings("malware.scan.detected", SUBJECT, Result.NOT_ASSESSED, tool=TOOL)
    with pytest.raises(ValueError, match="not_assessed_reason"):
        findings("malware.scan.detected", SUBJECT, Result.FAIL, tool=TOOL, reason="x")
    [f] = findings.not_assessed(
        ["malware.scan.detected"], SUBJECT, tool=TOOL, reason="clamav not installed"
    )
    assert f.not_assessed_reason == "clamav not installed"


def test_control_overrides(registry: RuleRegistry, catalog: ControlCatalog) -> None:
    mapping = ControlMapping(catalog, [ControlOverride("offline.*", ("SC-7", "AC-4"))])
    factory = FindingFactory(registry, mapping)
    f = factory("offline.telemetry.enabled", SUBJECT, Result.FAIL, tool=TOOL)
    assert f.controls == ("SC-7", "AC-4")
    with pytest.raises(RuleError):
        ControlMapping(catalog, [ControlOverride("x.*", ("ZZ-1",))])
