"""VM images as units: a disk or an appliance, with whatever describes it.

The VM handler claims each disk image (root: the image), each appliance (root: the OVA or OVF),
and Glance metadata (root: the image it describes). One unit per root carries the format, size,
dependencies, encryption and the Glance properties (``os_distro``, ``hw_*``) together.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence

from superscrubber104.core.canonical import JSON
from superscrubber104.core.interfaces import Assembly, Context
from superscrubber104.core.model import ArtifactRef, Unit, UnitClaim, UnitKind, UnitMember
from superscrubber104.handlers.common import name_of


class VmImageAssembler:
    name = "vm-image"
    version = "1"
    kind = UnitKind.VM_IMAGE

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for claim in claims:
            groups[claim.root].append(claim)
        assemblies = []
        for root, group in sorted(groups.items()):
            main = next((c for c in group if c.role in ("disk", "appliance")), None)
            if main is None:
                continue  # metadata for an image that is not in the delivery (the handler said so)
            attributes: dict[str, JSON] = {"type": main.role, **dict(main.facts)}
            for claim in group:
                if claim.role == "metadata":
                    attributes["glance"] = dict(claim.facts)
            members = sorted({(c.artifact, c.role): c.sha256 for c in group}.items())
            unit = Unit(
                kind=UnitKind.VM_IMAGE,
                name=f"{main.role} {name_of(root)}",
                root=root,
                members=tuple(UnitMember(role, ref, sha) for (ref, role), sha in members),
                attributes=attributes,
            )
            assemblies.append(Assembly(unit))
        return assemblies
