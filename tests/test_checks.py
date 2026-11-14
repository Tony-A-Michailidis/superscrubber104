"""Inventory and transfer checks that cannot be provoked on every filesystem end to end."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from airlock.catalog import ALL, builtin_registry
from airlock.checks.inventory import check_paths
from airlock.checks.transfer import check_transfer
from airlock.core.model import (
    Entry,
    EntryType,
    Finding,
    Provenance,
    Receipt,
    Result,
    ToolRef,
    Verdict,
)
from airlock.core.policy import Limits, Policy
from airlock.ledger import Ledger
from airlock.session import Session
from tests.helpers import NOW

SHA = "a" * 64
DIGEST = "sha256:" + "b" * 64


def by_rule(session: Session) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in session.ctx.recorder.findings:
        grouped.setdefault(finding.rule, []).append(finding)
    return grouped


def file(path: str, size: int = 1) -> Entry:
    return Entry(path, EntryType.FILE, size, {"sha256": SHA})


def test_integrity_and_authenticity_rules_are_final_and_nothing_else_is() -> None:
    registry = builtin_registry()
    assert len(registry) == len(ALL)
    final = {r.id for r in registry if r.final}
    # Hash mismatch, bad or missing signature, broken custody or ledger.
    assert {r.id for r in registry if r.id.startswith("integrity.")} <= final
    # Replay, in every form.
    assert {
        "replay.bundle.already-accepted",
        "replay.bundle.out-of-order",
        "replay.bundle.expired",
        "replay.clock.regression",
        "delta.base.unknown",
    } <= final
    # Wrong enclave or source.
    assert {
        "transfer.destination.mismatch",
        "transfer.destination.unbound",
        "transfer.source.unaccepted",
    } <= final
    # Content findings are policy matters: blockable, and overridable by a quorum.
    overridable = {
        r.id for r in registry if r.id.startswith(("archive.", "request.", "inventory."))
    }
    assert not overridable & final
    assert final - {r for r in final if r.startswith(("integrity.", "replay.", "transfer."))} == {
        "delta.base.unknown",
        "path.name.unsafe",  # the file cannot be stored at all, so there is nothing to approve
        "model.provenance.checksum-mismatch",  # a hash mismatch against the publisher's record
        # content that differs from the digest it is named or locked by
        "container.layer.digest-mismatch",
        "python.environment.hash-mismatch",
        "python.wheel.record-mismatch",
        "node.environment.integrity-mismatch",
        # a scanner that is not the one the policy pins
        "plugin.integrity.mismatch",
    }
    assert all(r.rationale for r in registry)


def test_path_checks() -> None:
    policy = replace(Policy.default(), limits=Limits(max_artifact_bytes=100, max_path_length=20))
    session = Session.start(policy, NOW)
    entries = [
        file("Models/Weights.bin"),
        file("models/weights.bin"),
        file("docs/" + "x" * 30),
        file("big.bin", size=101),
        Entry("link-in", EntryType.SYMLINK, link_target="app/main.py"),
        Entry("link-out", EntryType.SYMLINK, link_target="../../home/user/.ssh/id_ed25519"),
        Entry("link-abs", EntryType.SYMLINK, link_target="C:/Users/dev/secrets"),
        Entry("pipe", EntryType.OTHER),
    ]
    check_paths(entries, session.ctx)
    found = by_rule(session)
    assert found["path.case-collision"][0].detail["paths"] == [
        "Models/Weights.bin",
        "models/weights.bin",
    ]
    assert found["path.length.exceeded"][0].subject.display.startswith("docs/")
    assert found["size.artifact.exceeded"][0].subject.display == "big.bin"
    assert len(found["path.link.symlink"]) == 3
    assert {f.subject.display for f in found["path.link.escapes"]} == {"link-out", "link-abs"}
    assert found["path.special-file"][0].subject.display == "pipe"


def test_delta_base_must_be_an_accepted_snapshot(tmp_path: Path) -> None:
    provenance = Provenance(
        bundle_id="delta-1", created_at=NOW, tool=ToolRef("airlock", "0"), policy_digest=DIGEST
    )
    ledger = Ledger(tmp_path)

    def base_check(base: str) -> Result | None:
        session = Session.start(Policy.default(), NOW + timedelta(hours=1))
        check_transfer(provenance, base, ledger, session.ctx)
        findings = by_rule(session).get("delta.base.unknown")
        return findings[0].result if findings else None

    assert base_check(DIGEST) is Result.FAIL  # nothing has ever been accepted

    def receipt(verdict: Verdict) -> Receipt:
        return Receipt(
            bundle_id="full-1",
            manifest_digest=DIGEST,
            statement_digest=DIGEST,
            assessment_digest=DIGEST,
            policy_digest=Policy.default().digest,
            verdict=verdict,
            verified_at=NOW,
            bundle_created_at=NOW - timedelta(days=1),
        )

    ledger.append(receipt(Verdict.REFUSED), now=NOW, signer=None)
    assert base_check(DIGEST) is Result.FAIL  # a refused import is not a base
    ledger.append(receipt(Verdict.PASSED), now=NOW, signer=None)
    assert base_check(DIGEST) is None
    assert base_check("sha256:" + "c" * 64) is Result.FAIL

    session = Session.start(Policy.default(), NOW)
    check_transfer(provenance, DIGEST, None, session.ctx)
    assert by_rule(session)["delta.base.unknown"][0].result is Result.NOT_ASSESSED
