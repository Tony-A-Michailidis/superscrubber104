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
from airlock.core.serde import from_data, to_data
from airlock.core.signing import Signer, VerifyKey

EVENT_RECEIPT = "receipt"


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
        problems = chainlog.verify(self.events, resolve, require_signed=require_signed)
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
    def last_time(self) -> datetime | None:
        return self.events[-1].at if self.events else None

    @property
    def last_policy_digest(self) -> str | None:
        return self.receipts[-1].policy_digest if self.receipts else None

    def accepted_bundle(self, bundle_id: str) -> bool:
        return any(r.bundle_id == bundle_id for r in self.accepted)

    def accepted_snapshot(self, manifest_digest: str) -> bool:
        return any(r.manifest_digest == manifest_digest for r in self.accepted)

    def newest_accepted(self, source: str | None, stream: str) -> datetime | None:
        """Creation time of the newest accepted bundle from this source and stream."""
        times = [
            r.bundle_created_at for r in self.accepted if r.source == source and r.stream == stream
        ]
        return max(times, default=None)

    def append(self, receipt: Receipt, *, now: datetime, signer: Signer | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = to_data(receipt)
        assert isinstance(data, dict)  # noqa: S101
        self.events.append(chainlog.append(self.path, EVENT_RECEIPT, data, now=now, signer=signer))
        self.receipts.append(receipt)
