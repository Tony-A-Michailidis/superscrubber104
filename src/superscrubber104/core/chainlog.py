"""Append-only, hash-chained, per-event signed log (JSON Lines).

One format serves three uses: the chain-of-custody log that travels with a bundle, the receiving
side's ledger of receipts, and (phase 3) the gateway audit log. Each event names the digest of the
event before it, so edits and reordering are detectable. Truncation of the tail is not: consumers
must not rely on the *absence* of a later event.
"""

import base64
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from superscrubber104.core.canonical import JSON, canonical_bytes, sha256_digest
from superscrubber104.core.errors import Superscrubber104Error
from superscrubber104.core.serde import format_timestamp
from superscrubber104.core.signing import Signer, VerifyKey, pae

EVENT_TYPE = "application/vnd.superscrubber104.event+json"


class ChainError(Superscrubber104Error):
    """The log file is not parseable as a chain of events."""


@dataclass(frozen=True, slots=True)
class Event:
    seq: int
    prev: str | None  # digest of the previous event line; None for the first
    type: str
    at: datetime
    actor: str | None  # key id of the signer
    data: Mapping[str, JSON]
    sig: bytes | None

    def body(self) -> dict[str, JSON]:
        return {
            "seq": self.seq,
            "prev": self.prev,
            "type": self.type,
            "at": format_timestamp(self.at),
            "actor": self.actor,
            "data": dict(self.data),
        }

    def line(self) -> bytes:
        body = self.body()
        body["sig"] = base64.b64encode(self.sig).decode("ascii") if self.sig else None
        return canonical_bytes(body)

    @property
    def digest(self) -> str:
        return sha256_digest(self.line())

    def signed_message(self) -> bytes:
        return pae(EVENT_TYPE, canonical_bytes(self.body()))


def read(path: Path) -> list[Event]:
    """Parse a log. Structure only; call ``verify`` to check the chain and signatures."""
    if not path.exists():
        return []
    events = []
    for number, line in enumerate(path.read_bytes().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            events.append(
                Event(
                    seq=int(raw["seq"]),
                    prev=raw["prev"],
                    type=str(raw["type"]),
                    at=datetime.fromisoformat(raw["at"]),
                    actor=raw["actor"],
                    data=dict(raw["data"]),
                    sig=base64.b64decode(raw["sig"], validate=True) if raw["sig"] else None,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ChainError(f"{path}: line {number} is not a valid event: {exc}") from exc
    return events


def append(
    path: Path, type: str, data: Mapping[str, JSON], *, now: datetime, signer: Signer | None
) -> Event:
    """Append one event, chained to the current tail."""
    events = read(path)
    event = Event(
        seq=len(events) + 1,
        prev=events[-1].digest if events else None,
        type=type,
        at=now.replace(microsecond=0),
        actor=signer.key_id if signer else None,
        data=data,
        sig=None,
    )
    if signer:
        event = replace(event, sig=signer.sign(event.signed_message()))
    with path.open("ab") as stream:
        stream.write(event.line() + b"\n")
    return event


@dataclass(frozen=True, slots=True)
class ChainCheck:
    """Result of checking a log.

    ``broken`` lists structural damage: bad sequence, broken chaining, or a signature that does
    not verify under the key it names. Events are also sorted by what is known about their
    signer, because what an unknown signer means depends on the log: in a ledger this side wrote
    it is a problem; in a custody log that anyone handling the bundle may append to, such an
    event simply carries no weight.
    """

    broken: tuple[str, ...]
    verified: tuple[Event, ...]  # signed by a key ``resolve`` knows, and the signature holds
    unknown: tuple[Event, ...]  # signed by a key ``resolve`` does not know
    unsigned: tuple[Event, ...]

    def problems(self, *, require_signed: bool = True, allow_unknown: bool = False) -> list[str]:
        problems = list(self.broken)
        if not allow_unknown:
            problems += [f"event {e.seq} ({e.type}): signed by untrusted key" for e in self.unknown]
        if require_signed:
            problems += [f"event {e.seq} ({e.type}): not signed" for e in self.unsigned]
        return problems


def verify(events: list[Event], resolve: Callable[[str], VerifyKey | None]) -> ChainCheck:
    """Check sequence, chaining and signatures."""
    broken: list[str] = []
    verified: list[Event] = []
    unknown: list[Event] = []
    unsigned: list[Event] = []
    previous: Event | None = None
    for position, event in enumerate(events, start=1):
        if event.seq != position:
            broken.append(f"event {position}: sequence number is {event.seq}")
        expected = previous.digest if previous else None
        if event.prev != expected:
            broken.append(f"event {position}: does not chain to the event before it")
        if event.sig is None or event.actor is None:
            unsigned.append(event)
        else:
            key = resolve(event.actor)
            if key is None:
                unknown.append(event)
            elif key.verify(event.sig, event.signed_message()):
                verified.append(event)
            else:
                broken.append(f"event {position} ({event.type}): invalid signature")
        previous = event
    return ChainCheck(tuple(broken), tuple(verified), tuple(unknown), tuple(unsigned))
