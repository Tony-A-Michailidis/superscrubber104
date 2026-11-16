""".NET: ``packages.lock.json`` and ``.nupkg`` packages.

* ``packages.lock.json`` (``RestorePackagesWithLockFile``) lists every package per target framework
  with its resolved version and ``contentHash``, the base64 sha512 of the ``.nupkg``. ``dotnet
  restore --locked-mode`` refuses a package whose hash differs; each must be in the delivery (a
  local feed or a global packages folder).
* ``.nupkg`` files: identity and licence from the ``.nuspec``; whether the package carries a
  repository or author signature (``.signature.p7s``, recorded, not verified: see doc 29); and
  code that runs at build or install time (MSBuild ``.targets``/``.props`` under ``build/``,
  PowerShell scripts under ``tools/``). A ``.nupkg.sha512`` beside it (written by NuGet into the
  global packages folder) is compared.
"""

import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import quote

from airlock import __version__
from airlock.archive import ARCHIVE_ERRORS
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import ArtifactRef, LicenseRef, ToolRef, UnitKind, Verification
from airlock.handlers.common import TooLarge, mapping, name_of, read_json
from airlock.handlers.packages.locked import (
    b64_to_hex,
    build_hooks,
    check_sidecar,
    component,
    digest_hex,
    distribution_claim,
    lockfile_claim,
    requirement,
)

TOOL = ToolRef("airlock.nuget", __version__)
KIND = UnitKind.DOTNET_ENVIRONMENT
_HOOK_DIRS = ("build/", "buildtransitive/", "buildmultitargeting/")
_NUSPEC_LIMIT = 1 << 20


def normalize_version(version: str) -> str:
    """NuGet's normalised form: no build metadata, no leading zeros, at least three parts, and a
    fourth part only when it is not zero."""
    if not version.strip():
        return ""
    core, dash, prerelease = version.strip().split("+", 1)[0].partition("-")
    parts = [str(int(p)) if p.isdigit() else p for p in core.split(".")]
    while len(parts) < 3:
        parts.append("0")
    if len(parts) == 4 and parts[3] == "0":
        parts = parts[:3]
    return ".".join(parts) + (dash + prerelease if dash else "")


def nuget_purl(name: str, version: str) -> str:
    return f"pkg:nuget/{quote(name)}@{quote(version, safe='')}"


def _text(root: ET.Element, tag: str) -> str | None:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == tag:
            return (element.text or "").strip() or None
    return None


def _licence(root: ET.Element) -> str | None:
    """The SPDX expression, when the package declares one (``type="file"`` names a file)."""
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "license" and element.get("type") == "expression":
            return (element.text or "").strip() or None
    return None


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref).lower()
    if name == "packages.lock.json":
        return "nuget.lockfile"
    if name.endswith(".nupkg") and view.head(4) == b"PK\x03\x04":
        return "nuget.package"
    return None


class NuGetHandler:
    name = "nuget"
    version = "1"
    kinds = frozenset({"nuget.lockfile", "nuget.package"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 90) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        if _kind(artifact) == "nuget.lockfile":
            return self._lockfile(artifact)
        return self._package(artifact, ctx)

    def _lockfile(self, view: ArtifactView) -> Inspection:
        try:
            document = mapping(read_json(view, 64 << 20))
        except (TooLarge, ValueError) as exc:
            return Inspection(
                kind="nuget.lockfile", metadata={"nugetLock": {"error": str(exc)[:300]}}
            )
        requirements: dict[tuple[str, str], dict[str, object]] = {}
        frameworks = mapping(document.get("dependencies"))
        for packages in frameworks.values():
            for name, entry in mapping(packages).items():
                entry = mapping(entry)
                if entry.get("type") == "Project" or not entry.get("resolved"):
                    continue
                version = normalize_version(str(entry["resolved"]))
                content = b64_to_hex(str(entry.get("contentHash", "")))
                key = (name.lower(), version)
                requirements[key] = requirement(*key, [f"sha512:{content}"] if content else [])
        claim = lockfile_claim(
            view, KIND, "nuget", "packages.lock.json", list(requirements.values())
        )
        summary = {
            "version": document.get("version"),
            "frameworks": sorted(frameworks),
            "packages": len(requirements),
        }
        return Inspection(kind="nuget.lockfile", metadata={"nugetLock": summary}, claims=(claim,))

    def _package(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            with view.open() as stream, zipfile.ZipFile(stream) as archive:
                names = archive.namelist()
                nuspec = next(
                    (n for n in names if "/" not in n and n.lower().endswith(".nuspec")), None
                )
                root = None
                if nuspec is not None and archive.getinfo(nuspec).file_size <= _NUSPEC_LIMIT:
                    root = ET.fromstring(archive.read(nuspec))  # noqa: S314 - see the import
        except (*ARCHIVE_ERRORS, ET.ParseError, KeyError) as exc:
            return Inspection(kind="nuget.package", metadata={"nupkg": {"error": str(exc)[:300]}})
        if root is None:
            return Inspection(kind="nuget.package", metadata={"nupkg": {"error": "no .nuspec"}})
        package_id = _text(root, "id") or ""
        version = normalize_version(_text(root, "version") or "")
        lowered = [n.lower() for n in names]
        hooks = []
        if any(n.startswith(_HOOK_DIRS) and n.endswith((".targets", ".props")) for n in lowered):
            hooks.append("msbuild")
        if any(n.startswith("tools/") and n.endswith(".ps1") for n in lowered):
            hooks.append("powershell")
        build_hooks(view, ctx, TOOL, hooks)
        content_hash = digest_hex(view, "sha512")
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        recorded = view.resolve(name_of(view.ref) + ".sha512")
        if recorded is not None and recorded.size < 4096:
            with recorded.open() as stream:
                text = stream.read(4096).decode("ascii", "replace")
            check = check_sidecar(
                view, ctx, TOOL, "sha512", text, name_of(recorded.ref), "nuget-sha512"
            )
            if check is not None:
                verifications[view.ref] = (check,)
        licence = _licence(root)
        purl = nuget_purl(package_id, version)
        part = component(
            view,
            package_id,
            version,
            purl,
            licenses=(LicenseRef(expression=licence),) if licence else (),
            supplier=_text(root, "authors"),
        )
        claim = distribution_claim(
            view,
            KIND,
            "nuget",
            package_id.lower(),
            version,
            [f"sha512:{content_hash}"],
            part.bom_ref,
        )
        summary = {
            "id": package_id,
            "version": version,
            "signed": ".signature.p7s" in lowered,
            "hooks": hooks,
            "licence": licence,
        }
        return Inspection(
            kind="nuget.package",
            metadata={"nupkg": summary},
            components=(part,),
            claims=(claim,),
            verifications=verifications,
        )
