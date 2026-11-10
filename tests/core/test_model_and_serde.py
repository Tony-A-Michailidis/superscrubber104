import random
from datetime import UTC, datetime, timedelta, timezone

import pytest

from airlock.core.canonical import digest
from airlock.core.errors import SerializationError
from airlock.core.model import (
    Artifact,
    ArtifactRef,
    Assessment,
    Component,
    ComponentType,
    Decision,
    Disposition,
    EntryType,
    LicenseRef,
    Manifest,
    Receipt,
    Result,
    Stage,
    Subject,
    SubjectKind,
    Unit,
    UnitKind,
    UnitMember,
    UpstreamRef,
    Verdict,
    summarize,
)
from airlock.core.rules import FindingFactory
from airlock.core.serde import from_data, to_data
from tests.core.helpers import TOOL

SHA = "a" * 64
DIGEST = "sha256:" + "b" * 64


def artifact(path: str, *member: str) -> Artifact:
    return Artifact(
        ref=ArtifactRef(path, member),
        entry_type=EntryType.FILE,
        size=3,
        kind="unclassified",
        hashes={"sha256": SHA},
    )


def test_artifact_ref_display_and_validation() -> None:
    assert ArtifactRef("images/app.tar", ("layer.tar", "usr/bin/x")).display == (
        "images/app.tar!/layer.tar!/usr/bin/x"
    )
    with pytest.raises(ValueError):
        ArtifactRef("../escape")
    with pytest.raises(ValueError):
        ArtifactRef("ok.tar", ("/abs",))


def test_artifact_invariants() -> None:
    with pytest.raises(ValueError, match="sha256"):
        Artifact(ArtifactRef("a"), EntryType.FILE, 1, "unclassified")
    with pytest.raises(ValueError, match="link_target"):
        Artifact(ArtifactRef("a"), EntryType.SYMLINK, 0, "unclassified")
    with pytest.raises(ValueError, match="hex"):
        Artifact(ArtifactRef("a"), EntryType.FILE, 1, "x", hashes={"sha256": "A" * 64})
    link = Artifact(ArtifactRef("a"), EntryType.SYMLINK, 0, "unclassified", link_target="../b")
    assert link.sha256 is None


def test_subject_invariants() -> None:
    with pytest.raises(ValueError):
        Subject(SubjectKind.ARTIFACT)
    with pytest.raises(ValueError):
        Subject(SubjectKind.BUNDLE, unit="model-package:x")
    unit = Unit(UnitKind.MODEL_PACKAGE, "m", "models/m")
    subject = Subject.of_unit(unit)
    assert subject.display == "model-package:models/m"
    assert subject.path == "models/m"
    assert Subject.bundle().path is None


def test_manifest_is_deterministic_regardless_of_input_order() -> None:
    artifacts = [artifact(p) for p in ("b", "a/z", "a/b", "c.tar")] + [artifact("c.tar", "inner")]
    units = [Unit(UnitKind.MODEL_PACKAGE, n, n) for n in ("y", "x")]
    shuffled = artifacts[:]
    random.Random(1).shuffle(shuffled)
    m1 = Manifest.create(policy_digest=DIGEST, artifacts=artifacts, units=units)
    m2 = Manifest.create(policy_digest=DIGEST, artifacts=shuffled, units=units[::-1])
    assert digest(to_data(m1)) == digest(to_data(m2))
    assert [a.ref.display for a in m1.artifacts] == ["a/b", "a/z", "b", "c.tar", "c.tar!/inner"]


def test_manifest_rejects_unsorted_or_duplicate() -> None:
    with pytest.raises(ValueError):
        Manifest(policy_digest=DIGEST, artifacts=(artifact("b"), artifact("a")))
    with pytest.raises(ValueError):
        Manifest.create(policy_digest=DIGEST, artifacts=[artifact("a"), artifact("a")])
    with pytest.raises(ValueError, match="kind"):
        Manifest(policy_digest=DIGEST, artifacts=(), kind="Bundle")


def test_manifest_round_trip_with_camel_case() -> None:
    unit = Unit(
        UnitKind.MODEL_PACKAGE,
        "tiny",
        "models/tiny",
        members=(UnitMember("weights-shard", ArtifactRef("models/tiny/a")),),
        attributes={"shards": 1, "dtype": "bf16"},
    )
    manifest = Manifest.create(
        policy_digest=DIGEST,
        artifacts=[artifact("models/tiny/a")],
        units=[unit],
        request_digest=DIGEST,
    )
    data = to_data(manifest)
    assert isinstance(data, dict)
    assert {"apiVersion", "policyDigest", "requestDigest"} <= set(data)
    assert from_data(Manifest, data) == manifest


def test_component_round_trip() -> None:
    component = Component(
        bom_ref="pkg:huggingface/example-org/tiny@0123",
        type=ComponentType.MACHINE_LEARNING_MODEL,
        name="tiny",
        licenses=(LicenseRef(expression="Apache-2.0"),),
        upstream=UpstreamRef("huggingface", "example-org/tiny", revision="0123"),
        evidence=(ArtifactRef("models/tiny/a"),),
    )
    assert from_data(Component, to_data(component)) == component


def test_assessment_round_trip_and_summary(findings: FindingFactory) -> None:
    subject = Subject.of_artifact(ArtifactRef("models/x.pt"))
    f1 = findings("model.pickle.dangerous-import", subject, Result.FAIL, tool=TOOL)
    f2 = findings(
        "malware.scan.detected", subject, Result.NOT_ASSESSED, tool=TOOL, reason="clamav absent"
    )
    decisions = (
        Decision(f1.id, Disposition.BLOCK, "rules[0]"),
        Decision(f2.id, Disposition.WARN, "defaults.notAssessed"),
    )
    start = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    assessment = Assessment(
        tool=TOOL,
        stage=Stage.PACK,
        started_at=start,
        finished_at=start + timedelta(seconds=5),
        policy_digest=DIGEST,
        findings=(f1, f2),
        decisions=decisions,
        summary=summarize((f1, f2), decisions),
    )
    assert assessment.summary.verdict is Verdict.BLOCKED
    assert assessment.summary.results[Result.NOT_ASSESSED] == 1
    data = to_data(assessment)
    assert isinstance(data, dict)
    assert data["startedAt"] == "2026-11-10T12:00:00Z"
    assert from_data(Assessment, data) == assessment


def test_assessment_requires_one_decision_per_finding(findings: FindingFactory) -> None:
    f = findings("container.user.root", Subject.bundle(), Result.FAIL, tool=TOOL)
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="decision"):
        Assessment(
            tool=TOOL,
            stage=Stage.VERIFY,
            started_at=now,
            finished_at=now,
            policy_digest=DIGEST,
            findings=(f,),
            summary=summarize((f,), ()),
        )


def test_summary_verdicts() -> None:
    assert summarize((), ()).verdict is Verdict.PASSED
    needs = summarize((), (Decision("x", Disposition.REQUIRE_APPROVAL, "d", 1),))
    assert needs.verdict is Verdict.NEEDS_APPROVAL


def test_timestamps_normalised_to_utc() -> None:
    receipt = Receipt(
        manifest_digest=DIGEST,
        assessment_digest=DIGEST,
        policy_digest=DIGEST,
        verifier_key_id="ed25519:0123456789abcdef",
        verified_at=datetime(2026, 11, 10, 7, 0, tzinfo=timezone(timedelta(hours=-5))),
        verdict=Verdict.PASSED,
    )
    data = to_data(receipt)
    assert isinstance(data, dict)
    assert data["verifiedAt"] == "2026-11-10T12:00:00Z"
    assert from_data(Receipt, data) == receipt


def test_naive_timestamps_rejected() -> None:
    with pytest.raises(SerializationError):
        to_data(datetime(2026, 1, 1))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(extra=1), "unknown field"),
        (lambda d: d.pop("policyDigest"), "missing required field"),
        (lambda d: d["artifacts"][0].update(size="3"), "expected int"),
        (lambda d: d["artifacts"][0].update(size=True), "expected int"),
        (lambda d: d["artifacts"][0].update(entryType="device"), "not one of"),
        (lambda d: d.update(apiVersion="airlock/v9"), "apiVersion"),
    ],
)
def test_strict_decoding(mutate: object, message: str) -> None:
    data = to_data(Manifest.create(policy_digest=DIGEST, artifacts=[artifact("a")]))
    mutate(data)  # type: ignore[operator]
    with pytest.raises(SerializationError, match=message):
        from_data(Manifest, data)
