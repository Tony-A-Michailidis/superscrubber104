import pytest

from airlock.core.controls import ControlCatalog, ControlMapping, ControlOverride
from airlock.core.errors import RuleError
from airlock.core.model import Result, Severity, Subject
from airlock.core.rules import FindingFactory, Recorder, RuleRegistry, RuleSpec, finding_digest
from tests.core.helpers import RULES, TOOL

SUBJECT = Subject.of_path("models/x.pt")


def test_builtin_catalogue(catalog: ControlCatalog) -> None:
    assert catalog.framework == "nist-800-53r5"
    assert "SI-7" in catalog
    assert catalog.get("SR-11").family == "SR"
    assert len(list(catalog)) == 25


@pytest.mark.parametrize(
    ("control", "known"),
    [("SI-7", True), ("SI-7(1)", True), ("SI-7(x)", False), ("SI-7(1", False), ("XX-1(2)", False)],
)
def test_control_enhancements(catalog: ControlCatalog, control: str, known: bool) -> None:
    assert catalog.knows(control) is known


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


def test_finding_digest_covers_what_was_found(findings: FindingFactory) -> None:
    def make(imports: list[str]) -> str:
        finding = findings(
            "model.pickle.dangerous-import",
            SUBJECT,
            Result.FAIL,
            tool=TOOL,
            detail={"imports": [*imports]},
        )
        return finding_digest(finding)

    # Same id (same rule and subject), but an approval of one must not cover the other.
    assert make(["os.system"]) != make(["os.system", "subprocess.Popen"])
    assert make(["os.system"]) == make(["os.system"])


def test_finding_unknown_rule(findings: FindingFactory) -> None:
    with pytest.raises(RuleError):
        findings("not.registered", SUBJECT, Result.FAIL, tool=TOOL)


def test_not_assessed_needs_reason(findings: FindingFactory) -> None:
    with pytest.raises(ValueError, match="not_assessed_reason"):
        findings("malware.scan.detected", SUBJECT, Result.NOT_ASSESSED, tool=TOOL)
    with pytest.raises(ValueError, match="not_assessed_reason"):
        findings("malware.scan.detected", SUBJECT, Result.FAIL, tool=TOOL, reason="x")


def test_recorder_dedupes_and_orders(findings: FindingFactory) -> None:
    recorder = Recorder(findings)
    first = recorder.fail("offline.telemetry.enabled", SUBJECT, tool=TOOL)
    assert recorder.fail("offline.telemetry.enabled", SUBJECT, tool=TOOL) is first
    recorder.fail("container.user.root", Subject.of_path("b"), tool=TOOL)
    recorder.fail("container.user.root", Subject.of_path("a"), tool=TOOL)
    recorder.error("malware.scan.detected", SUBJECT, tool=TOOL, error="boom")
    assert [(f.rule, f.subject.display) for f in recorder.findings] == [
        ("container.user.root", "a"),
        ("container.user.root", "b"),
        ("malware.scan.detected", "models/x.pt"),
        ("offline.telemetry.enabled", "models/x.pt"),
    ]
    with pytest.raises(RuleError):
        recorder.passed("not.registered")
    assert {c.rule for c in recorder.coverage()} == {r.id for r in RULES}


def test_control_overrides(registry: RuleRegistry, catalog: ControlCatalog) -> None:
    mapping = ControlMapping(catalog, [ControlOverride("offline.*", ("SC-7", "AC-4"))])
    factory = FindingFactory(registry, mapping)
    f = factory("offline.telemetry.enabled", SUBJECT, Result.FAIL, tool=TOOL)
    assert f.controls == ("SC-7", "AC-4")
    with pytest.raises(RuleError):
        ControlMapping(catalog, [ControlOverride("x.*", ("ZZ-1",))])
