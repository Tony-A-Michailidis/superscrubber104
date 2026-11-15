"""Go: ``go.sum`` as a lockfile, the module cache, and vendored modules.

* ``go.sum`` lists the ``h1:`` hash of every module zip and ``go.mod`` the build may need. Without a
  ``vendor/`` directory, each must be in a module cache in the delivery
  (``.../pkg/mod/cache/download/<module>/@v/<version>.zip``, as ``GOFLAGS=-mod=mod GOPROXY=off``
  or a file-based ``GOPROXY`` would read it). With ``vendor/modules.txt`` the vendored modules are
  what the build uses, and go.sum's other entries are not needed.
* Module cache zips and ``.mod`` files are hashed the way the go command does (``h1:``); a
  ``.ziphash`` beside a zip is compared too.
"""

from urllib.parse import quote

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, ToolRef, UnitKind
from airlock.formats.golang import (
    cache_entry,
    mod_hash,
    parse_go_sum,
    parse_modules_txt,
    zip_hash,
)
from airlock.handlers.common import full_path, name_of, read_bytes, read_text
from airlock.handlers.packages.locked import (
    component,
    distribution_claim,
    lockfile_claim,
    requirement,
)

TOOL = ToolRef("airlock.go", __version__)
KIND = UnitKind.GO_ENVIRONMENT


def go_purl(module: str, version: str) -> str:
    return f"pkg:golang/{quote(module, safe='/')}@{quote(version, safe='')}"


def _kind(view: ArtifactView) -> str | None:
    if view.ref.nested:
        return None
    if name_of(view.ref) == "go.sum":
        return "go.sum"
    entry = cache_entry(full_path(view.ref))
    if entry is not None and entry[2] == "zip":
        return "go.module-zip"
    if entry is not None and entry[2] == "mod":
        return "go.module-mod"
    return None


class GoHandler:
    name = "go"
    version = "1"
    kinds = frozenset({"go.sum", "go.module-zip", "go.module-mod"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 90) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact) or "go.module-zip"
        if kind == "go.sum":
            return self._go_sum(artifact)
        module, version, _ = cache_entry(full_path(artifact.ref)) or ("", "", "")
        if kind == "go.module-mod":
            digest = mod_hash(read_bytes(artifact, 16 << 20))
            claim = distribution_claim(artifact, KIND, "go", f"{module}/go.mod", version, [digest])
            return Inspection(
                kind=kind,
                metadata={"goModule": {"module": module, "version": version}},
                claims=(claim,),
            )
        try:
            with artifact.open() as stream:
                digest = zip_hash(stream)
        except (OSError, ValueError) as exc:
            return Inspection(
                kind=kind, metadata={"goModule": {"module": module, "error": str(exc)[:300]}}
            )
        sibling = artifact.resolve(f"{name_of(artifact.ref).removesuffix('.zip')}.ziphash")
        if sibling is not None:
            recorded = read_bytes(sibling, 4096).decode("ascii", "replace").strip()
            if recorded != digest:
                ctx.recorder.fail(
                    "package.checksum-mismatch",
                    Subject.of_artifact(artifact.ref),
                    tool=TOOL,
                    detail={
                        "recordedIn": name_of(sibling.ref),
                        "algorithm": "h1",
                        "recorded": recorded,
                        "actual": digest,
                    },
                )
            else:
                ctx.recorder.passed("package.checksum-mismatch")
        purl = go_purl(module, version)
        part = component(artifact, module, version, purl)
        claim = distribution_claim(artifact, KIND, "go", module, version, [digest], part.bom_ref)
        return Inspection(
            kind=kind,
            metadata={"goModule": {"module": module, "version": version, "h1": digest}},
            components=(part,),
            claims=(claim,),
        )

    def _go_sum(self, view: ArtifactView) -> Inspection:
        entries = parse_go_sum(read_text(view, 64 << 20))
        modules_txt = view.resolve("vendor/modules.txt")
        if modules_txt is not None:
            hashes = {(e.module, e.version): e.hash for e in entries if not e.go_mod}
            requirements = [
                requirement(
                    module,
                    version,
                    [h] if (h := hashes.get((module, version))) else [],
                    vendored=True,
                )
                for module, version in parse_modules_txt(read_text(modules_txt, 64 << 20))
            ]
            mode = "vendor"
        else:
            requirements = [
                requirement(f"{e.module}/go.mod" if e.go_mod else e.module, e.version, [e.hash])
                for e in entries
            ]
            mode = "module-cache"
        claim = lockfile_claim(view, KIND, "go", "go.sum", requirements)
        summary = {"entries": len(entries), "mode": mode, "requirements": len(requirements)}
        return Inspection(kind="go.sum", metadata={"goSum": summary}, claims=(claim,))
