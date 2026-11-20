"""Signed approvals: clearing ``require-approval`` findings and overriding policy blockers.

An approval is a signed ``approved`` event in the bundle's custody log. It names one finding of
one manifest and carries a written justification. Whether it *counts* is decided only by the
verifying side:

* the signer must be pinned in the verifier's policy with the ``approve`` role and be valid today;
* the signer must not be the packer of the bundle (by key, or by holder);
* the approval must be for this manifest and for the finding exactly as the verifier found it;
* the finding must be one that approvals can clear. Integrity and authenticity failures never are.

A finding is cleared when approvals from enough *distinct holders* have been counted. Every
approval the verifier looked at, counted or not, is kept in the assessment as evidence.
"""

import json
from collections.abc import Sequence
from datetime import date, datetime
from pathlib import Path

from superscrubber104 import bundle as layout
from superscrubber104.core import chainlog
from superscrubber104.core.canonical import sha256_digest
from superscrubber104.core.errors import ConfigError, Superscrubber104Error
from superscrubber104.core.model import (
    Approval,
    ApprovalRecord,
    Assessment,
    Decision,
    Disposition,
    Finding,
)
from superscrubber104.core.policy import KeyRole, Policy
from superscrubber104.core.rules import finding_digest
from superscrubber104.core.serde import from_data, to_data
from superscrubber104.core.signing import Signer

EVENT_APPROVED = "approved"


def approve(
    bundle: Path,
    *,
    signer: Signer,
    findings: Sequence[str],
    justification: str,
    now: datetime,
    assessment_path: Path | None = None,
) -> list[Approval]:
    """Append one signed approval per finding to the bundle's custody log.

    ``assessment_path`` is the assessment the approver reviewed: the packer's by default, or this
    side's own ``assessment.verify.json``. Refuses anything that could never count, so nobody
    signs an approval in the belief that it does something.
    """
    path = assessment_path or bundle / layout.ASSESSMENT
    try:
        assessment = from_data(Assessment, json.loads(path.read_bytes()))
        manifest_digest = sha256_digest((bundle / layout.MANIFEST).read_bytes())
        events = chainlog.read(bundle / layout.CUSTODY)
    except (OSError, ValueError, Superscrubber104Error) as exc:
        raise ConfigError(f"cannot read {path} or the bundle it belongs to: {exc}") from exc
    if assessment.manifest_digest != manifest_digest:
        raise ConfigError(f"{path} is the assessment of a different manifest than this bundle's")
    if not events or events[0].type != layout.EVENT_PACKED:
        raise ConfigError("the bundle is not signed, so there is nothing to approve")
    if events[0].actor == signer.key_id:
        raise ConfigError("the packer cannot approve its own bundle")
    if not justification.strip():
        raise ConfigError("an approval needs a written justification")

    by_id = {f.id: f for f in assessment.findings}
    decisions = {d.finding: d for d in assessment.decisions}
    approvals = []
    for finding_id in dict.fromkeys(findings):
        finding = by_id.get(finding_id)
        if finding is None:
            raise ConfigError(f"no finding {finding_id!r} in {path}")
        decision = decisions[finding_id]
        if decision.final:
            raise ConfigError(
                f"{finding.rule} on {finding.subject.display} cannot be overridden: integrity "
                "and authenticity failures, and rules the policy marks as not overridable, "
                "are final"
            )
        if not decision.clearable:
            raise ConfigError(
                f"{finding.rule} on {finding.subject.display} is decided "
                f"'{decision.disposition.value}' and does not need approval"
            )
        approvals.append(
            Approval(manifest_digest, finding_id, finding_digest(finding), justification.strip())
        )
    for approval in approvals:
        data = to_data(approval)
        assert isinstance(data, dict)  # noqa: S101
        chainlog.append(bundle / layout.CUSTODY, EVENT_APPROVED, data, now=now, signer=signer)
    return approvals


def count_approvals(
    check: chainlog.ChainCheck,
    *,
    policy: Policy,
    manifest_digest: str | None,
    packers: Sequence[str],
    findings: Sequence[Finding],
    decisions: Sequence[Decision],
    today: date,
) -> tuple[set[str], tuple[ApprovalRecord, ...]]:
    """Decide which approvals in a checked custody log count.

    ``packers`` are the key ids that signed the bundle. Returns the ids of findings whose quorum
    is met, and a record of every approval seen.
    """
    by_id = {f.id: f for f in findings}
    decided = {d.finding: d for d in decisions}
    packer_holders = {s.holder for key_id in packers if (s := policy.signer(key_id)) is not None}
    holders: dict[str, set[str]] = {}
    records: list[ApprovalRecord] = []

    def record(event: chainlog.Event, reason: str | None, holder: str | None = None) -> None:
        data = event.data
        records.append(
            ApprovalRecord(
                finding=str(data.get("finding", "")),
                key_id=event.actor,
                holder=holder,
                justification=str(data.get("justification", "")),
                counted=reason is None,
                reason=reason,
            )
        )

    for event in check.unknown:
        if event.type == EVENT_APPROVED:
            record(event, "signed by a key this side does not know")
    for event in check.unsigned:
        if event.type == EVENT_APPROVED:
            record(event, "not signed")

    for event in check.verified:
        if event.type != EVENT_APPROVED:
            continue
        signer = policy.signer(event.actor or "")
        if signer is None:
            record(event, "the key is not pinned in this side's policy")
            continue
        try:
            approval = from_data(Approval, dict(event.data))
        except Superscrubber104Error as exc:
            record(event, f"malformed approval: {exc}", signer.holder)
            continue
        finding = by_id.get(approval.finding)
        decision = decided.get(approval.finding)
        reason: str | None = None
        if problem := signer.problem(KeyRole.APPROVE, today):
            reason = problem
        elif event.actor in packers or signer.holder in packer_holders:
            reason = "the packer cannot approve its own bundle"
        elif approval.manifest_digest != manifest_digest:
            reason = "the approval is for a different manifest"
        elif finding is None or decision is None:
            reason = "this side did not make that finding"
        elif approval.finding_digest != finding_digest(finding):
            reason = "what was found differs from what was approved"
        elif decision.final:
            reason = "this finding is final and cannot be overridden"
        elif not decision.clearable:
            reason = "this finding does not need approval"
        record(event, reason, signer.holder)
        if reason is None:
            holders.setdefault(approval.finding, set()).add(signer.holder)

    approved = {
        finding_id
        for finding_id, who in holders.items()
        if len(who) >= decided[finding_id].approvals_required
    }
    return approved, tuple(records)


def is_override(decision: Decision) -> bool:
    """Whether clearing this decision is the override of a blocker (not a routine approval)."""
    return decision.disposition is Disposition.BLOCK and decision.clearable
