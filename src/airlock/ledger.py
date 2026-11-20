"""The receiving side's record of every import it has verified.

A hash-chained log of receipts kept in a state directory. It is what makes checks across imports
possible: replayed or out-of-order bundles, deltas against a snapshot that was never accepted, a
clock that has gone backwards, and policy or key changes between imports.
"""

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from airlock.core import chainlog
from airlock.core.errors import AirlockError
from airlock.core.model import Receipt
from airlock.core.serde import format_timestamp, from_data, to_data
from airlock.core.signing import Signer, VerifyKey

EVENT_RECEIPT = "receipt"
EVENT_CLOCK = "clock-adjusted"


class Ledger:
    FILE = "ledger.jsonl"

    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / self.FILE
        self.events: list[chainlog.Event] = []
        self.receipts: list[Receipt] = []

    def load(
        self, resolve: Callable[[str], VerifyKey | None], *, require_signed: bool
    ) -> list[str]:
        """Read and check the ledger. Returns a list of problems (empty if sound)."""
        try:
            self.events = chainlog.read(self.path)
        except AirlockError as exc:
            return [str(exc)]
        check = chainlog.verify(self.events, resolve)
        problems = check.problems(require_signed=require_signed)
        self.receipts = []
        for event in self.events:
            if event.type != EVENT_RECEIPT:
                continue
            try:
                self.receipts.append(from_data(Receipt, dict(event.data)))
            except AirlockError as exc:
                problems.append(f"event {event.seq}: unreadable receipt: {exc}")
        return problems

    @property
    def accepted(self) -> list[Receipt]:
        return [r for r in self.receipts if r.accepted]

    @property
    def high_water(self) -> datetime | None:
        """The latest time recorded since the clock was last deliberately adjusted.

        The maximum, not the last entry: an import attempted while the clock is wrong must not
        quietly lower the mark and so cure the regression it just reported.
        """
        start = max((i for i, e in enumerate(self.events) if e.type == EVENT_CLOCK), default=0)
        return max((e.at for e in self.events[start:]), default=None)

    @property
    def pending_clock_adjustments(self) -> list[chainlog.Event]:
        """Clock adjustments recorded since the last receipt (not yet shown in any assessment)."""
        last = max((i for i, e in enumerate(self.events) if e.type == EVENT_RECEIPT), default=-1)
        return [e for e in self.events[last + 1 :] if e.type == EVENT_CLOCK]

    def adjust_clock(self, *, now: datetime, reason: str, signer: Signer | None) -> chainlog.Event:
        """Record that the clock was deliberately set back, and restart the high-water mark.

        This is the recovery path for a host whose clock drifted ahead and was then corrected.
        It is an explicit, signed, hash-chained event; it never happens implicitly.
        """
        previous = self.high_water
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = chainlog.append(
            self.path,
            EVENT_CLOCK,
            {
                "reason": reason,
                "previousHighWater": format_timestamp(previous) if previous else None,
                "clock": format_timestamp(now),
            },
            now=now,
            signer=signer,
        )
        self.events.append(event)
        return event

    @property
    def last_policy_digest(self) -> str | None:
        return self.receipts[-1].policy_digest if self.receipts else None

    def accepted_bundle(self, bundle_id: str) -> bool:
        return any(r.bundle_id == bundle_id for r in self.accepted)

    def accepted_receipts(self, bundle_id: str) -> list[Receipt]:
        return [r for r in self.accepted if r.bundle_id == bundle_id]

    def accepted_snapshot(self, manifest_digest: str) -> bool:
        return any(r.manifest_digest == manifest_digest for r in self.accepted)

    def newest_accepted(self, source: str | None, stream: str) -> datetime | None:
        """Creation time of the newest accepted bundle from this source and stream."""
        times = [
            r.bundle_created_at for r in self.accepted if r.source == source and r.stream == stream
        ]
        return max(times, default=None)

    def newest_snapshot(self, identity: str) -> str | None:
        """The newest accepted metadata time for one repository (ISO 8601, UTC)."""
        times = [r.snapshots[identity] for r in self.accepted if identity in r.snapshots]
        return max(times, default=None)

    def append(self, receipt: Receipt, *, now: datetime, signer: Signer | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = to_data(receipt)
        assert isinstance(data, dict)  # noqa: S101
        self.events.append(chainlog.append(self.path, EVENT_RECEIPT, data, now=now, signer=signer))
        self.receipts.append(receipt)
