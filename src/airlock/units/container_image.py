"""Container image units: one per image archive or OCI layout, with an SBOM component per image.

The image handler has already checked integrity and completeness; the unit records what the
delivery contains, for the SBOM and for staging into a registry.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from urllib.parse import quote

from airlock import __version__
from airlock.core.canonical import JSON
from airlock.core.interfaces import Assembly, Context
from airlock.core.model import (
    ArtifactRef,
    Component,
    ComponentType,
    ToolRef,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
)
from airlock.handlers.containers import image_name
from airlock.units.facts import as_str

TOOL = ToolRef("airlock.container-image", __version__)


def oci_purl(repository: str, tag: str | None, digest: str) -> str:
    """pkg:oci/<name>@<digest>?repository_url=<repository>&tag=<tag>"""
    name = repository.rsplit("/", 1)[-1]
    purl = f"pkg:oci/{name}@{quote(digest, safe='')}?repository_url={quote(repository, safe='/')}"
    return purl + (f"&tag={quote(tag, safe='')}" if tag else "")


def _component(root: ArtifactRef, image: dict[str, JSON]) -> Component:
    repository, tag = image_name(as_str(image.get("name")))
    digest = as_str(image.get("manifestDigest")) or as_str(image.get("configDigest"))
    config = as_str(image.get("configDigest"))
    properties = {
        "airlock:os": image.get("os"),
        "airlock:architecture": image.get("architecture"),
        "airlock:user": image.get("user") or "root",
        "airlock:layers": image.get("layers"),
    }
    return Component(
        bom_ref=f"container:{root.display}:{digest or repository}",
        type=ComponentType.CONTAINER,
        name=repository,
        version=tag,
        purl=oci_purl(repository, tag, digest) if digest else None,
        hashes={"sha256": config.removeprefix("sha256:")} if config else {},
        evidence=(root,),
        properties={k: str(v) for k, v in properties.items() if v is not None},
    )


class ContainerImageAssembler:
    name = "container-image"
    version = "1"
    kind = UnitKind.CONTAINER_IMAGE

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for c in claims:
            groups[c.root].append(c)
        assemblies = []
        for root, group in sorted(groups.items()):
            images = [i for c in group if isinstance(i := c.facts.get("image"), dict)]
            components = tuple(_component(root, image) for image in images)
            name = next((n for i in images if (n := as_str(i.get("name")))), "untagged image")
            unique = {(c.artifact, c.role): c.sha256 for c in group}
            unit = Unit(
                kind=UnitKind.CONTAINER_IMAGE,
                name=name,
                root=root,
                members=tuple(UnitMember(r, a, s) for (a, r), s in sorted(unique.items())),
                components=tuple(c.bom_ref for c in components),
                attributes={"images": list(images)},
            )
            assemblies.append(Assembly(unit, components))
        return assemblies
