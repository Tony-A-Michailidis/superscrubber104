"""Checks that bind a bundle to one transfer: destination, source, age, replay and ordering."""

from airlock.analyzer import TOOL
from airlock.core.interfaces import Context
from airlock.core.model import Provenance, Subject
from airlock.ledger import Ledger

_LEDGER_RULES = (
    "replay.clock.regression",
    "replay.bundle.already-accepted",
    "replay.bundle.out-of-order",
    "policy.digest.changed",
)


def check_policy(ctx: Context) -> None:
    for waiver in ctx.policy.expired_waivers(ctx.now.date()):
        ctx.recorder.fail(
            "policy.waiver.expired",
            Subject.policy(),
            tool=TOOL,
            detail={"waiver": waiver.id, "expired": waiver.expires.isoformat()},
            discriminator=waiver.id,
        )


def check_transfer(
    provenance: Provenance, base: str | None, ledger: Ledger | None, ctx: Context
) -> None:
    policy, recorder, subject = ctx.policy, ctx.recorder, Subject.bundle()

    identity = policy.identity
    if identity is None:
        recorder.not_assessed(
            ("transfer.destination.mismatch", "transfer.source.unaccepted"),
            subject,
            tool=TOOL,
            reason="the policy does not set identity.enclave",
        )
    else:
        if provenance.destination is None:
            recorder.fail("transfer.destination.unbound", subject, tool=TOOL)
        elif provenance.destination != identity.enclave:
            recorder.fail(
                "transfer.destination.mismatch",
                subject,
                tool=TOOL,
                detail={"destination": provenance.destination, "enclave": identity.enclave},
            )
        else:
            recorder.passed("transfer.destination.mismatch")
        if identity.accept_sources and provenance.source not in identity.accept_sources:
            recorder.fail(
                "transfer.source.unaccepted",
                subject,
                tool=TOOL,
                detail={"source": provenance.source, "accepted": [*identity.accept_sources]},
            )
        else:
            recorder.passed("transfer.source.unaccepted")

    if policy.max_bundle_age is None:
        recorder.not_assessed(
            ("replay.bundle.expired",),
            subject,
            tool=TOOL,
            reason="the policy does not set transfer.maxBundleAge",
        )
    elif ctx.now - provenance.created_at > policy.max_bundle_age:
        recorder.fail(
            "replay.bundle.expired",
            subject,
            tool=TOOL,
            detail={
                "ageSeconds": int((ctx.now - provenance.created_at).total_seconds()),
                "maxSeconds": int(policy.max_bundle_age.total_seconds()),
            },
        )
    else:
        recorder.passed("replay.bundle.expired")

    if ledger is None:
        rules = (*_LEDGER_RULES, "delta.base.unknown") if base else _LEDGER_RULES
        recorder.not_assessed(
            rules,
            subject,
            tool=TOOL,
            reason="no state directory was given, so there is no record of earlier imports",
        )
        return

    last = ledger.last_time
    if last is not None and ctx.now < last:
        recorder.fail(
            "replay.clock.regression", subject, tool=TOOL, detail={"lastEntry": last.isoformat()}
        )
    else:
        recorder.passed("replay.clock.regression")

    if ledger.accepted_bundle(provenance.bundle_id):
        recorder.fail("replay.bundle.already-accepted", subject, tool=TOOL)
    else:
        recorder.passed("replay.bundle.already-accepted")

    newest = ledger.newest_accepted(provenance.source, provenance.stream)
    if newest is not None and provenance.created_at < newest:
        recorder.fail(
            "replay.bundle.out-of-order",
            subject,
            tool=TOOL,
            detail={"stream": provenance.stream, "newestAccepted": newest.isoformat()},
        )
    else:
        recorder.passed("replay.bundle.out-of-order")

    previous = ledger.last_policy_digest
    if previous is not None and previous != policy.digest:
        recorder.fail(
            "policy.digest.changed",
            Subject.policy(),
            tool=TOOL,
            detail={"previous": previous, "current": policy.digest},
        )
    else:
        recorder.passed("policy.digest.changed")

    if base is not None:
        if ledger.accepted_snapshot(base):
            recorder.passed("delta.base.unknown")
        else:
            recorder.fail("delta.base.unknown", subject, tool=TOOL, detail={"base": base})
