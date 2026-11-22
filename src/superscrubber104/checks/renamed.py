"""Packages under another name: say so, never skip them.

Zarf packages and Hauler hauls are recognised by the file names their tools give them
(``zarf-package-*.tar.zst``, ``haul*.tar.zst``), because the head of the file cannot tell: Zarf
writes ``zarf.yaml`` last, and both are usually zstd. A renamed one is still walked as an archive,
so its content is inventoried and inspected, but the package checks (the checksum chain, the
signature, completeness, deploy actions; or the layout's digests) would not run. This records
them as not assessed on the archive, with how to fix the name.
"""

from collections.abc import Sequence

from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Artifact, ArtifactRef, Subject
from superscrubber104.handlers import hauler, zarf

_LAYOUT_KINDS = frozenset({hauler.KIND, "container.image.archive", "container.image.oci-layout"})
_SIGNATURE_RULES = ("upstream.signature.invalid", "upstream.signature.untrusted")


def _container(ref: ArtifactRef) -> tuple[str, str, Subject]:
    """Display of the archive holding member ``ref``, of the one around that, and a subject."""
    container = "!/".join((ref.path, *ref.member[:-1]))
    outer = "!/".join((ref.path, *ref.member[:-2]))  # the .zst around a .tar, if any
    holder = ArtifactRef(ref.path, ref.member[:-1], unsafe=ref.unsafe)
    return container, outer, Subject.of_artifact(holder)


def check_renamed_packages(artifacts: Sequence[Artifact], ctx: Context) -> None:
    kinds = {a.ref.display: a.kinds for a in artifacts}

    def handled(container: str, outer: str, accepted: frozenset[str]) -> bool:
        return bool(accepted & {*kinds.get(container, ()), *kinds.get(outer, ())})

    for artifact in artifacts:
        ref = artifact.ref
        if not ref.member:
            continue
        name = ref.member[-1]
        if name == "zarf.yaml":
            container, outer, subject = _container(ref)
            if f"{container}!/checksums.txt" not in kinds:
                continue  # a project's source tree, not a built package
            if handled(container, outer, frozenset({zarf.KIND})):
                continue
            ctx.recorder.not_assessed(
                zarf.RULES,
                subject,
                tool=zarf.TOOL,
                reason="holds zarf.yaml and checksums.txt like a Zarf package, but is not named "
                "like one, so it was walked as a plain archive; name it zarf-package-<name>-"
                "<arch>-<version>.tar.zst (or zarf-init-...) to have it checked as a package",
            )
        elif name == "oci-layout":
            container, outer, subject = _container(ref)
            if f"{container}!/index.json" not in kinds:
                continue
            if handled(container, outer, _LAYOUT_KINDS):
                continue
            ctx.recorder.not_assessed(
                (*hauler.LAYOUT_RULES, *_SIGNATURE_RULES),
                subject,
                tool=hauler.TOOL,
                reason="holds an OCI image layout (oci-layout, index.json), but was not "
                "recognised as an image archive or a Hauler haul by its name, so its images "
                "were not checked; name a haul haul.tar.zst (or haul-<name>.tar.zst)",
            )
