"""Zarf packages as units: the package, its definition, checksums, signature and contents.

The Zarf handler claims the package (with what its definition declares and what was verified)
and the members that make it up; the unit holds them together. The images in the package form
their own container-image unit, rooted at ``images/index.json``.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence

from superscrubber104.core.interfaces import Assembly, Context
from superscrubber104.core.model import ArtifactRef, Unit, UnitClaim, UnitKind, UnitMember
from superscrubber104.handlers.common import name_of
from superscrubber104.units.facts import as_str


class ZarfPackageAssembler:
    name = "zarf-package"
    version = "1"
    kind = UnitKind.ZARF_PACKAGE

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for claim in claims:
            groups[claim.root].append(claim)
        assemblies = []
        for root, group in sorted(groups.items()):
            package = next((c for c in group if c.role == "package"), None)
            if package is None:
                continue
            name = as_str(package.facts.get("name")) or name_of(root)
            label = (
                "Zarf init package"
                if package.facts.get("kind") == "ZarfInitConfig"
                else "Zarf package"
            )
            members = sorted({(c.artifact, c.role): c.sha256 for c in group}.items())
            unit = Unit(
                kind=UnitKind.ZARF_PACKAGE,
                name=f"{label} {name}",
                root=root,
                members=tuple(UnitMember(role, ref, sha) for (ref, role), sha in members),
                attributes=dict(package.facts),
            )
            assemblies.append(Assembly(unit))
        return assemblies
