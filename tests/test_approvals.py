"""Approvals and overrides.

Policy blockers can be overridden for one bundle by a quorum of approvers with a written
justification. Integrity and authenticity failures cannot be overridden by anyone.
"""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from airlock import bundle as layout
from airlock.approvals import EVENT_APPROVED, approve
from airlock.core import chainlog
from airlock.core.errors import ConfigError
from airlock.core.model import Approval, ApprovalRecord, Assessment, Disposition, Verdict
from airlock.core.policy import Policy
from airlock.core.rules import finding_digest
from airlock.core.serde import from_data, to_data
from airlock.core.signing import SigningKey, generate_key
from airlock.pack import pack
from airlock.session import EXIT_BLOCKED, EXIT_OK, EXIT_REFUSED, exit_code
from airlock.summary import render
from airlock.verify import VerifyResult, verify
from tests.helpers import NOW, Site, make_delivery, make_site, zip_bytes

TRAVERSAL = "archive.member.path-traversal"  # high -> block: a policy blocker, quorum of 2
UNDECLARED = "request.artifact.undeclared"  # medium -> require-approval, 1 approval
REASON = "Vendor archive; reviewed member by member, extracted only inside the build sandbox."


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return make_site(tmp_path / "site")


@pytest.fixture
def bundle(site: Site, tmp_path: Path) -> Path:
    """A signed bundle with one policy blocker and one finding that needs approval."""
    delivery = make_delivery(tmp_path / "delivery")
    (delivery / "vendor/evil.zip").write_bytes(zip_bytes({"../../etc/cron.d/x": b"* * * * *"}))
    (delivery / "surprise.bin").write_bytes(b"not in the request")
    result = pack(
        [delivery],
        tmp_path / "bundle",
        signer=site.pack_key,
        policy=Policy.default(),
        request_path=site.request,
        now=NOW,
    )
    assert result.signed
    assert result.assessment.summary.verdict is Verdict.BLOCKED
    return result.bundle


def check(site: Site, bundle: Path, **policy: str) -> VerifyResult:
    return verify(bundle, policy=site.policy(**policy), now=NOW + timedelta(hours=1))


def finding_id(assessment: Assessment, rule: str) -> str:
    [finding] = [f for f in assessment.findings if f.rule == rule]
    return finding.id


def sign_off(
    site: Site, bundle: Path, who: str, *rules: str, minutes: int = 10, reason: str = REASON
) -> None:
    assessment = check(site, bundle).assessment
    approve(
        bundle,
        signer=site.approvers[who],
        findings=[finding_id(assessment, rule) for rule in rules],
        justification=reason,
        now=NOW + timedelta(minutes=minutes),
    )


def records(result: VerifyResult, counted: bool) -> list[ApprovalRecord]:
    return [r for r in result.assessment.approvals if r.counted is counted]


def raw_approval(
    site: Site, bundle: Path, signer: SigningKey | None, rule: str = TRAVERSAL, **changes: str
) -> None:
    """Append an approval event directly, bypassing the checks ``approve`` makes up front."""
    assessment = check(site, bundle).assessment
    [finding] = [f for f in assessment.findings if f.rule == rule]
    assert assessment.manifest_digest is not None
    data = to_data(
        Approval(assessment.manifest_digest, finding.id, finding_digest(finding), REASON)
    )
    assert isinstance(data, dict)
    data.update(changes)
    chainlog.append(
        bundle / layout.CUSTODY,
        EVENT_APPROVED,
        data,
        now=NOW + timedelta(minutes=30),
        signer=signer,
    )


# --- the intended path --------------------------------------------------------------------------


def test_blocker_is_overridden_by_a_quorum_with_justification(site: Site, bundle: Path) -> None:
    before = check(site, bundle)
    decisions = {d.finding: d for d in before.assessment.decisions}
    blocker = decisions[finding_id(before.assessment, TRAVERSAL)]
    assert (blocker.disposition, blocker.approvals_required, blocker.final) == (
        Disposition.BLOCK,
        2,
        False,
    )
    assert decisions[finding_id(before.assessment, UNDECLARED)].approvals_required == 1
    assert before.assessment.summary.verdict is Verdict.BLOCKED
    assert exit_code(before.assessment) == EXIT_BLOCKED

    # One approver clears the require-approval finding, but is not a quorum for the blocker.
    sign_off(site, bundle, "alice", TRAVERSAL, UNDECLARED)
    one = check(site, bundle)
    assert one.assessment.summary.verdict is Verdict.BLOCKED
    assert len(records(one, counted=True)) == 2
    text = render(one.assessment)
    assert "BLOCK    archive.member.path-traversal" in text
    assert "approvals: 1 of 2 (alice)" in text
    assert "APPROVED request.artifact.undeclared" in text

    # A second key held by the same person does not make a quorum.
    sign_off(site, bundle, "alice-backup", TRAVERSAL, minutes=20)
    assert check(site, bundle).assessment.summary.verdict is Verdict.BLOCKED

    # A second person does.
    sign_off(site, bundle, "bob", TRAVERSAL, minutes=30)
    final = check(site, bundle)
    assert final.assessment.summary.verdict is Verdict.PASSED
    assert exit_code(final.assessment) == EXIT_OK
    assert "OVERRIDE archive.member.path-traversal" in render(final.assessment)
    assert "approvals: 2 of 2 (alice, bob)" in render(final.assessment)

    # The override is evidence: who, with which key, and why, in the signed log and the assessment.
    override = [r for r in records(final, counted=True) if r.holder == "bob"]
    assert override[0].justification == REASON
    assert override[0].key_id == site.approvers["bob"].key_id
    events = chainlog.read(bundle / layout.CUSTODY)
    assert [e.type for e in events] == ["packed", *["approved"] * 4]
    assert all(e.sig for e in events)
    assert final.receipt is not None
    assert final.receipt.accepted
    # The blocker is still recorded as a blocker; it was overridden, not erased.
    assert final.assessment.summary.dispositions[Disposition.BLOCK] == 1
    assert from_data(Assessment, json.loads(layout.encode(final.assessment))) == final.assessment


def test_receiving_side_can_approve_from_its_own_assessment(
    site: Site, bundle: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    result = verify(bundle, policy=site.policy(), out=out, now=NOW + timedelta(hours=1))
    undeclared = finding_id(result.assessment, UNDECLARED)
    approve(
        bundle,
        signer=site.approvers["bob"],
        findings=[undeclared],
        justification="Agreed with the system owner by phone; request to be amended.",
        now=NOW + timedelta(hours=2),
        assessment_path=out / "assessment.verify.json",
    )
    after = check(site, bundle)
    assert [r.finding for r in records(after, counted=True)] == [undeclared]


# --- what never counts --------------------------------------------------------------------------


def test_the_packer_cannot_approve(site: Site, bundle: Path) -> None:
    assessment = check(site, bundle).assessment
    with pytest.raises(ConfigError, match="packer cannot approve"):
        approve(
            bundle,
            signer=site.pack_key,
            findings=[finding_id(assessment, UNDECLARED)],
            justification=REASON,
            now=NOW,
        )
    # Even if such an approval is written into the log by other means, it is not counted,
    # although the packer's key is pinned with the approve role.
    raw_approval(site, bundle, site.pack_key, UNDECLARED)
    result = check(site, bundle)
    [rejected] = records(result, counted=False)
    assert rejected.reason == "the packer cannot approve its own bundle"
    assert records(result, counted=True) == []
    assert "NOT COUNTED approval" in render(result.assessment)


def test_integrity_failures_cannot_be_approved(site: Site, bundle: Path, tmp_path: Path) -> None:
    (bundle / "payload/app/main.py").write_text("print('tampered')")
    out = tmp_path / "out"
    result = verify(bundle, policy=site.policy(), out=out, now=NOW + timedelta(hours=1))
    assert result.assessment.summary.verdict is Verdict.REFUSED
    mismatch = finding_id(result.assessment, "integrity.hash.mismatch")
    with pytest.raises(ConfigError, match="cannot be overridden"):
        approve(
            bundle,
            signer=site.approvers["alice"],
            findings=[mismatch],
            justification="It is fine, really.",
            now=NOW,
            assessment_path=out / "assessment.verify.json",
        )
    # Forcing approvals into the log changes nothing either.
    for who in ("alice", "bob"):
        raw_approval(site, bundle, site.approvers[who], "integrity.hash.mismatch")
    forced = check(site, bundle)
    assert forced.assessment.summary.verdict is Verdict.REFUSED
    assert exit_code(forced.assessment) == EXIT_REFUSED
    assert {r.reason for r in records(forced, counted=False)} == {
        "this finding is final and cannot be overridden"
    }


def test_policy_can_make_a_blocker_non_overridable(site: Site, bundle: Path) -> None:
    strict = site.policy(
        """
        rules:
          - {rule: "archive.member.path-traversal", disposition: block, overridable: false}
        """
    )
    for who in ("alice", "bob"):
        sign_off(site, bundle, who, TRAVERSAL)
    result = verify(bundle, policy=strict, now=NOW + timedelta(hours=1))
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert len(records(result, counted=False)) == 2


def test_approvals_from_unknown_or_unsuitable_keys(site: Site, bundle: Path) -> None:
    raw_approval(site, bundle, generate_key())  # a key this side has never seen
    raw_approval(site, bundle, None)  # not signed at all
    raw_approval(site, bundle, site.receipt_key)  # pinned, but not as an approver
    result = check(site, bundle)
    reasons = sorted(str(r.reason) for r in records(result, counted=False))
    assert reasons == [
        "key does not have the 'approve' role",
        "not signed",
        "signed by a key this side does not know",
    ]
    # Anyone may append to the custody log; that alone is not damage.
    assert "integrity.custody.broken" not in {f.rule for f in result.assessment.findings}
    assert result.assessment.summary.verdict is Verdict.BLOCKED

    sign_off(site, bundle, "alice", TRAVERSAL, minutes=40)
    expired = check(site, bundle, approver_extra="      validUntil: 2026-01-01\n")
    assert "key expired on 2026-01-01" in {r.reason for r in records(expired, counted=False)}
    revoked = check(site, bundle, approver_extra="      revoked: true\n")
    assert "key is revoked" in {r.reason for r in records(revoked, counted=False)}


def test_approval_is_bound_to_the_manifest_and_to_what_was_found(site: Site, bundle: Path) -> None:
    raw_approval(site, bundle, site.approvers["alice"], manifestDigest="sha256:" + "0" * 64)
    raw_approval(site, bundle, site.approvers["bob"], findingDigest="sha256:" + "0" * 64)
    raw_approval(site, bundle, site.approvers["bob"], finding="0" * 16)
    reasons = {r.reason for r in records(check(site, bundle), counted=False)}
    assert reasons == {
        "the approval is for a different manifest",
        "what was found differs from what was approved",
        "this side did not make that finding",
    }


def test_edited_approval_breaks_the_custody_log(site: Site, bundle: Path) -> None:
    sign_off(site, bundle, "alice", TRAVERSAL)
    path = bundle / layout.CUSTODY
    path.write_bytes(path.read_bytes().replace(b"Vendor archive", b"Vendor ARCHIVE"))
    result = check(site, bundle)
    assert "integrity.custody.broken" in {f.rule for f in result.assessment.findings}
    assert result.assessment.approvals == ()  # nothing in a damaged log is counted
    assert exit_code(result.assessment) == EXIT_REFUSED


def test_approve_refuses_what_could_never_count(site: Site, bundle: Path, tmp_path: Path) -> None:
    assessment = check(site, bundle).assessment
    alice = site.approvers["alice"]
    undeclared = finding_id(assessment, UNDECLARED)
    with pytest.raises(ConfigError, match="written justification"):
        approve(bundle, signer=alice, findings=[undeclared], justification="  ", now=NOW)
    with pytest.raises(ConfigError, match="no finding"):
        approve(bundle, signer=alice, findings=["f" * 16], justification=REASON, now=NOW)
    allowed = next(f.id for f in assessment.findings if f.rule == "inventory.artifact.unclassified")
    with pytest.raises(ConfigError, match="does not need approval"):
        approve(bundle, signer=alice, findings=[allowed], justification=REASON, now=NOW)

    other = pack(
        [make_delivery(tmp_path / "other-delivery")],
        tmp_path / "other",
        signer=site.pack_key,
        policy=Policy.default(),
        now=NOW,
    )
    with pytest.raises(ConfigError, match="different manifest"):
        approve(
            bundle,
            signer=alice,
            findings=[undeclared],
            justification=REASON,
            now=NOW,
            assessment_path=other.bundle / layout.ASSESSMENT,
        )
    assert [e.type for e in chainlog.read(bundle / layout.CUSTODY)] == ["packed"]


def test_the_packer_cannot_approve_with_a_second_key(site: Site, bundle: Path) -> None:
    """The rule is about the person, not the key: quorums and exclusions go by holder."""
    two_keys = replace(site, approvers={**site.approvers, "packer-second": generate_key()})
    assessment = verify(bundle, policy=two_keys.policy(), now=NOW).assessment
    approve(
        bundle,
        signer=two_keys.approvers["packer-second"],
        findings=[finding_id(assessment, UNDECLARED)],
        justification=REASON,
        now=NOW + timedelta(minutes=5),
    )
    result = verify(bundle, policy=two_keys.policy(), now=NOW + timedelta(hours=1))
    [rejected] = records(result, counted=False)
    assert rejected.holder == "packer"
    assert rejected.reason == "the packer cannot approve its own bundle"
    assert result.assessment.summary.verdict is Verdict.BLOCKED
