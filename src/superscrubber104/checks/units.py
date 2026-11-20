"""Conformance of the units that formed to the units the transfer request declared."""

from collections.abc import Sequence

from superscrubber104.analyzer import TOOL
from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Subject, Unit
from superscrubber104.core.request import TransferRequest


def check_request_units(
    request: TransferRequest | None, units: Sequence[Unit], ctx: Context
) -> None:
    """Each content entry declared with ``unit:`` must have produced a unit of that kind.

    A unit counts for an entry when any of its members lies under the entry's paths.
    """
    if request is None:
        return
    for entry in request.contents:
        if entry.unit is None:
            continue
        formed = [
            unit
            for unit in units
            if unit.kind is entry.unit
            and any(entry.covers(m.artifact.display) for m in unit.members)
        ]
        if formed:
            ctx.recorder.passed("request.content.unit-missing")
            continue
        ctx.recorder.fail(
            "request.content.unit-missing",
            Subject.request(),
            tool=TOOL,
            detail={"content": entry.name, "unit": entry.unit.value, "paths": [*entry.paths]},
            discriminator=entry.name,
        )
