import random
from datetime import UTC, datetime, timedelta, timezone

import pytest

from superscrubber104.core.canonical import canonical_bytes, digest
from superscrubber104.core.errors import SerializationError
from superscrubber104.core.model import (
    Analysis,
    Artifact,
    ArtifactRef,
    Assessment,
    Component,
    ComponentType,
    Decision,
    Disposition,
    Entry,
    EntryType,
    LicenseRef,
    Manifest,
    Provenance,
    Receipt,
    Requirement,
    Result,
    Stage,
    Subject,
    SubjectKind,
    ToolRef,
    TrustLevel,
    Unit,
    UnitKind,
    UnitMember,
    UpstreamRef,
    Verdict,
    Verification,
    summarize,
)
from superscrubber104.core.rules import FindingFactory, Recorder
from superscrubber104.core.serde import from_data, to_data
from tests.core.helpers import TOOL

SHA = "a" * 64
DIGEST = "sha256:" + "b" * 64


def entry(path: str) -> Entry:
    return Entry(path, EntryType.FILE, size=3, hashes={"sha256": SHA})


def test_artifact_ref_display_and_validation() -> None:
    ref = ArtifactRef("images/app.tar", ("layer.tar", "usr/bin/x"))
    assert ref.display == "images/app.tar!/layer.tar!/usr/bin/x"
    assert ref.nested
    with pytest.raises(ValueError):
        ArtifactRef("../escape")
    with pytest.raises(ValueError):
        ArtifactRef("ok.tar", ("/abs",))


def test_hostile_names_can_be_recorded_and_reported() -> None:
    ref = ArtifactRef("ok.zip").child("../../etc/passwd", unsafe=True)
    assert ref.unsafe
    assert ref.child("inner").unsafe  # everything below an unsafe name stays unsafe
    subject = Subject.of_artifact(ref)
    assert subject.display == "ok.zip!/../../etc/passwd"
    assert from_data(Subject, to_data(subject)) == subject
    with pytest.raises(ValueError):
        ArtifactRef("ok.zip", ("",), unsafe=True)


def test_entry_invariants() -> None:
    with pytest.raises(ValueError, match="sha256"):
        Entry("a", EntryType.FILE, 1)
    with pytest.raises(ValueError, match="link_target"):
        Entry("a", EntryType.SYMLINK)
    with pytest.raises(ValueError, match="hex"):
        Entry("a", EntryType.FILE, 1, hashes={"sha256": "A" * 64})
    with pytest.raises(ValueError):
        Entry("../a", EntryType.DIRECTORY)
    assert Entry("a", EntryType.SYMLINK, link_target="../b").sha256 is None


def test_subject_invariants() -> None:
    with pytest.raises(ValueError):
        Subject(SubjectKind.ARTIFACT)
    with pytest.raises(ValueError):
        Subject(SubjectKind.BUNDLE, unit="model-package:x")
    unit = Unit(UnitKind.MODEL_PACKAGE, "m", ArtifactRef("models/m"))
    subject = Subject.of_unit(unit)
    assert subject.display == "model-package:models/m"
    assert subject.path == "models/m"
    assert Subject.bundle().path is None
    assert Subject.of_component("pkg:pypi/x@1").display == "pkg:pypi/x@1"
    located = Subject.of_artifact(ArtifactRef("app/config.json"), locator="/servers/0/tools/2")
    assert located.display == "app/config.json#/servers/0/tools/2"
    assert located.path == "app/config.json"


def test_manifest_is_deterministic_and_content_only() -> None:
    entries = [entry(p) for p in ("b", "a/z", "a/b", "c.tar")]
    shuffled = entries[:]
    random.Random(1).shuffle(shuffled)
    m1 = Manifest.create(entries, chunk_size=64)
    m2 = Manifest.create(shuffled, chunk_size=64)
    assert digest(to_data(m1)) == digest(to_data(m2))
    assert [e.path for e in m1.entries] == ["a/b", "a/z", "b", "c.tar"]
    data = to_data(m1)
    assert isinstance(data, dict)
    # Nothing about policy, request, tool or time: the digest identifies content alone.
    assert set(data) == {"apiVersion", "kind", "entries", "chunkSize", "extensions"}


def test_manifest_invariants() -> None:
    with pytest.raises(ValueError):
        Manifest(entries=(entry("b"), entry("a")), chunk_size=1)
    with pytest.raises(ValueError):
        Manifest.create([entry("a"), entry("a")], chunk_size=1)
    with pytest.raises(ValueError, match="kind"):
        Manifest(entries=(), chunk_size=1, kind="Bundle")
    carried = Entry("a", EntryType.FILE, 3, {"sha256": SHA}, carried=True)
    with pytest.raises(ValueError, match="base"):
        Manifest.create([carried], chunk_size=1)
    delta = Manifest.create([carried, entry("b")], chunk_size=1, base=DIGEST)
    assert from_data(Manifest, to_data(delta)) == delta


def test_unit_digest_depends_on_content_not_location() -> None:
    def unit(root: str, sha: str = SHA) -> Unit:
        ref = ArtifactRef(root)
        return Unit(
            UnitKind.MODEL_PACKAGE,
            "tiny",
            ref,
            members=(
                UnitMember("weights-shard", ArtifactRef(f"{root}/a"), sha),
                UnitMember("tokenizer", ArtifactRef(f"{root}/t"), "c" * 64),
            ),
        )

    assert unit("models/a").digest == unit("elsewhere/b").digest
    assert unit("models/a").digest != unit("models/a", "d" * 64).digest
    assert unit("models/a").id == "model-package:models/a"


def test_unit_can_live_inside_an_archive_and_require_other_units() -> None:
    root = ArtifactRef("images/app.tar", ("layer.tar", "opt/model"))
    adapter = Unit(
        UnitKind.MODEL_PACKAGE,
        "adapter",
        root,
        requires=(
            Requirement("base-model", "tiny", UnitKind.MODEL_PACKAGE, digest=DIGEST),
            Requirement("runtime", "ollama", version="0.5", satisfied_by="high-side:inventory"),
        ),
        attributes={"rank": 16},
    )
    assert adapter.id == "model-package:images/app.tar!/layer.tar!/opt/model"
    analysis = Analysis.create(TOOL, [], units=[adapter])
    assert from_data(Analysis, to_data(analysis)) == analysis


def test_artifact_and_component_round_trip() -> None:
    artifact = Artifact(
        ArtifactRef("tools/run"),
        EntryType.FILE,
        size=10,
        kinds=("binary.elf", "model.gguf"),
        hashes={"sha256": SHA},
        mode=0o755,
        handlers=(ToolRef("binary", "1"),),
        verifications=(
            Verification("gpg", TrustLevel.SIGNATURE, Result.PASS, signer="ABCD", anchor="vendor"),
        ),
    )
    assert artifact.kind == "binary.elf"
    assert from_data(Artifact, to_data(artifact)) == artifact
    component = Component(
        bom_ref="pkg:huggingface/example-org/tiny@0123",
        type=ComponentType.MACHINE_LEARNING_MODEL,
        name="tiny",
        licenses=(LicenseRef(expression="Apache-2.0"),),
        upstream=UpstreamRef("huggingface", "example-org/tiny", revision="0123"),
        evidence=(ArtifactRef("models/tiny/a"),),
        depends_on=("pkg:pypi/tokenizers@0.20",),
    )
    assert from_data(Component, to_data(component)) == component
    assert TrustLevel.SIGNATURE.rank > TrustLevel.PINNED_CHECKSUM.rank > TrustLevel.ASSERTED.rank


def test_assessment_round_trip_summary_and_coverage(findings: FindingFactory) -> None:
    recorder = Recorder(findings)
    subject = Subject.of_path("models/x.pt")
    f1 = recorder.fail("model.pickle.dangerous-import", subject, tool=TOOL)
    recorder.not_assessed(["malware.scan.detected"], subject, tool=TOOL, reason="clamav absent")
    recorder.passed("container.user.root", 3)
    f2 = next(f for f in recorder.findings if f.rule == "malware.scan.detected")
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
        findings=recorder.findings,
        decisions=decisions,
        coverage=recorder.coverage(),
        summary=summarize(recorder.findings, decisions),
    )
    assert assessment.summary.verdict is Verdict.BLOCKED
    assert not assessment.refused
    coverage = {c.rule: c for c in assessment.coverage}
    assert coverage["container.user.root"].passed == 3
    assert coverage["model.pickle.dangerous-import"].failed == 1
    assert coverage["malware.scan.detected"].not_assessed == 1
    assert not coverage["offline.telemetry.enabled"].exercised  # visible as never run
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
    pending = (Decision("x", Disposition.REQUIRE_APPROVAL, "d", 1),)
    assert summarize((), pending).verdict is Verdict.NEEDS_APPROVAL
    assert summarize((), pending, approved={"x"}).verdict is Verdict.PASSED
    # A policy blocker stands until its override quorum is met.
    blocked = (*pending, Decision("y", Disposition.BLOCK, "d", 2))
    assert summarize((), blocked).verdict is Verdict.BLOCKED
    assert summarize((), blocked, approved={"x"}).verdict is Verdict.BLOCKED
    assert summarize((), blocked, approved={"x", "y"}).verdict is Verdict.PASSED
    # An integrity or authenticity failure is final: approvals change nothing.
    refused = (*blocked, Decision("z", Disposition.BLOCK, "final", final=True))
    assert summarize((), refused, approved={"x", "y", "z"}).verdict is Verdict.REFUSED
    assert not refused[-1].clearable
    assert blocked[-1].clearable


def test_provenance_and_receipt_round_trip() -> None:
    created = datetime(2026, 11, 10, 7, 0, tzinfo=timezone(timedelta(hours=-5)))
    provenance = Provenance(
        bundle_id="b1",
        created_at=created,
        tool=TOOL,
        policy_digest=DIGEST,
        source="dev",
        destination="enclave-b",
    )
    data = to_data(provenance)
    assert isinstance(data, dict)
    assert data["createdAt"] == "2026-11-10T12:00:00Z"
    assert from_data(Provenance, data) == provenance
    receipt = Receipt(
        bundle_id="b1",
        manifest_digest=DIGEST,
        statement_digest=DIGEST,
        assessment_digest=DIGEST,
        policy_digest="sha384:" + "c" * 96,  # other digest algorithms are representable
        verdict=Verdict.PASSED,
        verified_at=created,
        bundle_created_at=created,
        enclave="enclave-b",
    )
    assert receipt.accepted
    assert from_data(Receipt, to_data(receipt)) == receipt
    with pytest.raises(ValueError):
        Receipt(
            bundle_id="b1",
            manifest_digest="md5:abc",
            statement_digest=DIGEST,
            assessment_digest=DIGEST,
            policy_digest=DIGEST,
            verdict=Verdict.PASSED,
            verified_at=created,
            bundle_created_at=created,
        )


def test_floats_and_naive_timestamps_are_rejected() -> None:
    with pytest.raises(SerializationError):
        to_data(datetime(2026, 1, 1))
    unit = Unit(UnitKind.MODEL_PACKAGE, "m", ArtifactRef("m"), attributes={"temperature": 0.7})  # type: ignore[dict-item]
    with pytest.raises(SerializationError):
        canonical_bytes(to_data(unit))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(extra=1), "unknown field"),
        (lambda d: d.pop("chunkSize"), "missing required field"),
        (lambda d: d["entries"][0].update(size="3"), "expected int"),
        (lambda d: d["entries"][0].update(size=True), "expected int"),
        (lambda d: d["entries"][0].update(entryType="device"), "not one of"),
        (lambda d: d["entries"][0].update(path="../../x"), "invalid segment"),
        (lambda d: d.update(apiVersion="superscrubber104/v9"), "apiVersion"),
    ],
)
def test_strict_decoding(mutate: object, message: str) -> None:
    data = to_data(Manifest.create([entry("a")], chunk_size=64))
    mutate(data)
    with pytest.raises(SerializationError, match=message):
        from_data(Manifest, data)
