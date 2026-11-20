"""Mirror rollback: never accept repository metadata older than a snapshot already accepted.

Each repo-mirror unit records the time of every repository it holds (``snapshots``: identity such
as ``apt:Ubuntu/noble-security`` -> metadata date). Receipts carry them, so the receiving side's
ledger knows the newest snapshot it accepted for each repository. A replayed or older mirror
would quietly undo security updates already imported; that is ``repo.metadata.rollback``.
"""

from collections.abc import Sequence
from datetime import datetime

from superscrubber104.analyzer import TOOL
from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Subject, SubjectKind, Unit, UnitKind
from superscrubber104.ledger import Ledger


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def mirror_snapshots(units: Sequence[Unit]) -> dict[str, str]:
    """Every repository snapshot in the delivery: identity -> metadata time."""
    out: dict[str, str] = {}
    for unit in units:
        if unit.kind is not UnitKind.REPO_MIRROR:
            continue
        snapshots = unit.attributes.get("snapshots")
        if isinstance(snapshots, dict):
            out.update({str(k): str(v) for k, v in snapshots.items()})
    return out


def check_rollback(units: Sequence[Unit], ledger: Ledger | None, ctx: Context) -> None:
    for unit in sorted(units, key=lambda u: u.id):
        snapshots = unit.attributes.get("snapshots")
        if (
            unit.kind is not UnitKind.REPO_MIRROR
            or not isinstance(snapshots, dict)
            or not snapshots
        ):
            continue
        subject = Subject(SubjectKind.UNIT, unit=unit.id)
        if ledger is None:
            ctx.recorder.not_assessed(
                ("repo.metadata.rollback",),
                subject,
                tool=TOOL,
                reason="no ledger (--state) to compare repository snapshots with",
            )
            continue
        for identity, when in sorted(snapshots.items()):
            accepted = ledger.newest_snapshot(identity)
            newest, current = _time(accepted), _time(when)
            if newest is not None and current is not None and current < newest:
                ctx.recorder.fail(
                    "repo.metadata.rollback",
                    subject,
                    tool=TOOL,
                    detail={"repository": identity, "snapshot": when, "accepted": accepted},
                    discriminator=identity,
                )
            else:
                ctx.recorder.passed("repo.metadata.rollback")
