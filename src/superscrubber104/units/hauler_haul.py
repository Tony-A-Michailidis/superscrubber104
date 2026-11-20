"""Hauler hauls as units: what one haul carries, and which artifacts arrived signed.

The Hauler handler claims the haul with a summary of its images, charts, files, signatures,
attestations and SBOMs. The images also form a container-image unit rooted at the haul.
"""

from collections.abc import Iterable, Sequence

from superscrubber104.core.interfaces import Assembly, Context
from superscrubber104.core.model import Unit, UnitClaim, UnitKind, UnitMember
from superscrubber104.handlers.common import name_of


class HaulAssembler:
    name = "hauler-haul"
    version = "1"
    kind = UnitKind.HAULER_HAUL

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        assemblies = []
        for claim in sorted(claims, key=lambda c: c.root):
            if claim.role != "haul":
                continue
            unit = Unit(
                kind=UnitKind.HAULER_HAUL,
                name=f"Hauler haul {name_of(claim.root)}",
                root=claim.root,
                members=(UnitMember(claim.role, claim.artifact, claim.sha256),),
                attributes=dict(claim.facts),
            )
            assemblies.append(Assembly(unit))
        return assemblies
