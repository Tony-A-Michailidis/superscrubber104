"""Operating-system package databases and release files, wherever they appear.

Inside container layers (and, later, VM images) these say what the OS layer contains. Debian and
Ubuntu (``var/lib/dpkg/status``) and Alpine (``lib/apk/db/installed``) databases are plain text and
parsed here. RPM databases (``rpmdb.sqlite``) are read by the Linux package handler.
"""

import hashlib
from urllib.parse import quote

from superscrubber104 import __version__
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import ArtifactRef, Component, ComponentType, LicenseRef, ToolRef
from superscrubber104.handlers.common import full_path, read_text

TOOL = ToolRef("superscrubber104.os-packages", __version__)
_LIMIT = 64 << 20


def _bom_ref(purl: str, ref: ArtifactRef) -> str:
    """Unique per occurrence: the same package appears in many layers and images."""
    return f"{purl}#{hashlib.sha256(ref.display.encode()).hexdigest()[:12]}"


def _paragraphs(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if current:
                records.append(current)
            current, key = {}, None
        elif line[0] in " \t" and key:
            current[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            current[key] = value.strip()
    if current:
        records.append(current)
    return records


def _dpkg(view: ArtifactView) -> list[Component]:
    components = []
    for record in _paragraphs(read_text(view, _LIMIT)):
        name, version = record.get("Package"), record.get("Version")
        if not name or not version or "installed" not in record.get("Status", "installed"):
            continue
        arch = record.get("Architecture", "")
        vendor = "ubuntu" if "ubuntu" in version.lower() else "debian"
        purl = f"pkg:deb/{vendor}/{quote(name)}@{quote(version, safe='')}" + (
            f"?arch={arch}" if arch else ""
        )
        components.append(
            Component(
                bom_ref=_bom_ref(purl, view.ref),
                type=ComponentType.LIBRARY,
                name=name,
                version=version,
                purl=purl,
                supplier=record.get("Maintainer"),
                evidence=(view.ref,),
                properties={"superscrubber104:package-db": "dpkg"},
            )
        )
    return components


def _apk(view: ArtifactView) -> list[Component]:
    components = []
    record: dict[str, str] = {}
    for line in [*read_text(view, _LIMIT).splitlines(), ""]:
        if line.strip():
            if len(line) > 2 and line[1] == ":":
                record.setdefault(line[0], line[2:])
            continue
        if record.get("P") and record.get("V"):
            name, version, arch = record["P"], record["V"], record.get("A", "")
            purl = f"pkg:apk/alpine/{quote(name)}@{quote(version, safe='')}" + (
                f"?arch={arch}" if arch else ""
            )
            components.append(
                Component(
                    bom_ref=_bom_ref(purl, view.ref),
                    type=ComponentType.LIBRARY,
                    name=name,
                    version=version,
                    purl=purl,
                    licenses=(LicenseRef(name=record["L"]),) if record.get("L") else (),
                    evidence=(view.ref,),
                    properties={"superscrubber104:package-db": "apk"},
                )
            )
        record = {}
    return components


def _os_release(view: ArtifactView) -> tuple[dict[str, str], list[Component]]:
    values = {}
    for line in read_text(view, 64 << 10).splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().isidentifier():
            values[key.strip()] = value.strip().strip("\"'")
    identifier = values.get("ID")
    if not identifier:
        return values, []
    component = Component(
        bom_ref=_bom_ref(f"os:{identifier}@{values.get('VERSION_ID', '')}", view.ref),
        type=ComponentType.OPERATING_SYSTEM,
        name=identifier,
        version=values.get("VERSION_ID"),
        evidence=(view.ref,),
        properties={"superscrubber104:pretty-name": values.get("PRETTY_NAME", identifier)},
    )
    return values, [component]


class OSPackageHandler:
    name = "os-packages"
    version = "1"
    kinds = frozenset({"os.dpkg-status", "os.apk-installed", "os.release"})

    @staticmethod
    def _kind(view: ArtifactView) -> str | None:
        path = full_path(view.ref)
        if path.endswith("var/lib/dpkg/status"):
            return "os.dpkg-status"
        if path.endswith("lib/apk/db/installed"):
            return "os.apk-installed"
        if path.endswith(("etc/os-release", "usr/lib/os-release")):
            return "os.release"
        return None

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = self._kind(artifact)
        return Detection(kind, 80) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = self._kind(artifact)
        assert kind is not None  # noqa: S101
        if kind == "os.release":
            values, components = _os_release(artifact)
            summary = {
                k: values[k]
                for k in ("ID", "VERSION_ID", "PRETTY_NAME", "VERSION_CODENAME")
                if k in values
            }
            return Inspection(
                kind=kind, metadata={"osRelease": summary}, components=tuple(components)
            )
        components = _dpkg(artifact) if kind == "os.dpkg-status" else _apk(artifact)
        return Inspection(
            kind=kind,
            metadata={"osPackages": {"packages": len(components)}},
            components=tuple(components),
        )
