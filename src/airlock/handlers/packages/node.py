"""npm packages, installed node_modules, package tarballs and lockfiles.

* ``package.json``: name, version, licence and the scripts npm runs on install (``preinstall``,
  ``install``, ``postinstall``, and a native build when ``binding.gyp`` is present). A dependency
  in ``node_modules`` or a package tarball is someone else's code running on install; the
  project's own scripts are reported at lower severity.
* Package tarballs (``name-1.2.3.tgz``): their integrity (sha512 and sha1, the forms lockfiles
  record) is computed so the environment assembler can match them to lockfile entries.
* Lockfiles (``package-lock.json``/``npm-shrinkwrap.json``, ``yarn.lock`` v1 and Berry,
  ``pnpm-lock.yaml``): every locked package with version, integrity and source. Packages resolved
  from git or URLs are reported here; whether the delivery can satisfy the lockfile offline is
  checked by the Node environment assembler.

Nothing is installed and no script is run.
"""

import base64
import hashlib
import json
import re
import tarfile
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import yaml

from airlock import __version__
from airlock.checks.licences import check_licences
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import (
    ArtifactRef,
    Component,
    ComponentType,
    LicenseRef,
    Severity,
    Subject,
    ToolRef,
    UnitKind,
)
from airlock.core.yamlio import load_untrusted_yaml
from airlock.handlers.common import (
    TooLarge,
    full_path,
    make_claim,
    mapping,
    name_of,
    read_json,
    read_text,
)
from airlock.licences import Declared, normalise_identifier

TOOL = ToolRef("airlock.node", __version__)
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
_TARBALL = re.compile(r"^(?P<name>.+?)-(?P<version>\d+\.\d+\.\d+[^/]*?)\.tgz$")
_REMOTE = re.compile(
    r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?://(?!registry\.)[^/]+/.+\.git)"
)
_TARBALL_LIMIT = 256 << 20


def npm_purl(name: str, version: str) -> str:
    if name.startswith("@") and "/" in name:
        scope, _, base = name.partition("/")
        return f"pkg:npm/{quote(scope)}/{quote(base)}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name)}@{quote(version, safe='')}"


def _bom_ref(purl: str, ref: ArtifactRef) -> str:
    return f"{purl}#{hashlib.sha256(ref.display.encode()).hexdigest()[:12]}"


def _licence(manifest: dict[str, Any]) -> list[Declared]:
    value = manifest.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    values = (
        [value]
        if isinstance(value, str)
        else [v.get("type") for v in manifest.get("licenses") or [] if isinstance(v, dict)]
    )
    return [
        Declared(
            "package.json",
            normalise_identifier(v) or (v if " OR " in v or " AND " in v else None),
            v,
        )
        for v in values
        if isinstance(v, str) and v.strip()
    ]


def _install_scripts(manifest: dict[str, Any], native: bool) -> dict[str, str]:
    scripts = mapping(manifest.get("scripts"))
    found = {k: str(scripts[k])[:300] for k in _INSTALL_SCRIPTS if isinstance(scripts.get(k), str)}
    if native and "install" not in found:
        found["install"] = "node-gyp rebuild (implicit: binding.gyp is present)"
    return found


_PACKAGE_ROOT = re.compile(r"(?:^|/)node_modules/(?:@[^/]+/)?[^/]+$")


def _installed_path(path: str) -> tuple[str, str] | None:
    """('project/dir', 'node_modules/a/node_modules/b') for a package.json under node_modules."""
    index = f"/{path}".find("/node_modules/")
    if index < 0:
        return None
    prefix = path[: max(index - 1, 0)] if index else ""
    return prefix, path[len(prefix) + (1 if prefix else 0) :].removesuffix("/package.json")


def _is_package_root(location: str) -> bool:
    """node_modules/a or node_modules/@scope/a: not a package.json nested inside a package."""
    return _PACKAGE_ROOT.search(location) is not None


def _root_for(ref: ArtifactRef, prefix: str) -> ArtifactRef:
    if not ref.member:
        return ArtifactRef(prefix or ".")
    outer = ref.member[:-1]
    return ArtifactRef(ref.path, (*outer, prefix) if prefix else outer)


def _record_scripts(ctx: Context, view: ArtifactView, scripts: dict[str, str], scope: str) -> None:
    if scripts:
        ctx.recorder.fail(
            "npm.package.install-script",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"scripts": scripts, "scope": scope},
            attributes={"scope": scope},
            severity=Severity.LOW if scope == "project" else None,
        )
    else:
        ctx.recorder.passed("npm.package.install-script")


def _package_json(view: ArtifactView, ctx: Context) -> Inspection:
    manifest = read_json(view, 8 << 20)
    if not isinstance(manifest, dict):
        return Inspection(kind="unclassified")
    path = full_path(view.ref)
    if view.ref.member and path == "package/package.json":
        return Inspection(
            kind="npm.package-manifest"
        )  # inside a tarball: the tarball handler reports it
    name, version = manifest.get("name"), manifest.get("version")
    native = view.resolve("binding.gyp") is not None or manifest.get("gypfile") is True
    installed = _installed_path(path)
    if installed and not _is_package_root(installed[1]):
        return Inspection(kind="npm.package-manifest")  # a nested manifest npm never acts on
    scope = "dependency" if installed else "project"
    _record_scripts(ctx, view, _install_scripts(manifest, native), scope)
    components: tuple[Component, ...] = ()
    if isinstance(name, str) and isinstance(version, str):
        purl = npm_purl(name, version)
        declared = _licence(manifest)
        component = Component(
            bom_ref=_bom_ref(purl, view.ref),
            type=ComponentType.LIBRARY if installed else ComponentType.APPLICATION,
            name=name,
            version=version,
            purl=purl,
            licenses=tuple(LicenseRef(expression=d.identifier, name=d.name) for d in declared),
            evidence=(view.ref,),
        )
        components = (component,)
        if installed and declared:
            check_licences(Subject.of_component(component.bom_ref), declared, ctx)
    facts: dict[str, object] = {"name": name, "version": version}
    if installed:
        prefix, location = installed
        facts["path"] = location
        facts["bomRef"] = components[0].bom_ref if components else None
        claim = make_claim(
            view, UnitKind.NODE_ENVIRONMENT, "installed", facts, root=_root_for(view.ref, prefix)
        )
    else:
        deps = mapping(manifest.get("dependencies"))
        facts["dependencies"] = len(deps)
        claim = make_claim(view, UnitKind.NODE_ENVIRONMENT, "project", facts)
    summary = {
        "name": name,
        "version": version,
        "scope": scope,
        "private": manifest.get("private") is True,
    }
    return Inspection(
        kind="npm.package-manifest",
        metadata={"npmPackage": summary},
        components=components,
        claims=(claim,),
    )


def _tarball(view: ArtifactView, ctx: Context) -> Inspection:
    sha512, sha1 = hashlib.sha512(), hashlib.sha1(usedforsecurity=False)
    with view.open() as stream:
        while block := stream.read(1 << 20):
            sha512.update(block)
            sha1.update(block)
    manifest: dict[str, Any] = {}
    if view.size <= _TARBALL_LIMIT:
        try:
            with view.open() as stream, tarfile.open(fileobj=stream, mode="r:gz") as archive:
                for member in archive:
                    if (
                        member.isfile()
                        and member.name.removeprefix("./").count("/") == 1
                        and member.name.endswith("/package.json")
                    ):
                        handle = archive.extractfile(member)
                        if handle is not None and member.size < 8 << 20:
                            loaded = json.loads(handle.read())
                            manifest = loaded if isinstance(loaded, dict) else {}
                        break
        except (tarfile.TarError, ValueError, OSError, EOFError):
            manifest = {}
    match = _TARBALL.match(name_of(view.ref))
    name = (
        manifest.get("name")
        if isinstance(manifest.get("name"), str)
        else (match["name"] if match else None)
    )
    version = (
        manifest.get("version")
        if isinstance(manifest.get("version"), str)
        else (match["version"] if match else None)
    )
    if not (isinstance(name, str) and isinstance(version, str)):
        return Inspection(kind="unclassified")
    _record_scripts(ctx, view, _install_scripts(manifest, False), "dependency")
    purl = npm_purl(name, version)
    declared = _licence(manifest)
    component = Component(
        bom_ref=_bom_ref(purl, view.ref),
        type=ComponentType.LIBRARY,
        name=name,
        version=version,
        purl=purl,
        licenses=tuple(LicenseRef(expression=d.identifier, name=d.name) for d in declared),
        hashes={"sha512": sha512.hexdigest(), "sha256": view.sha256 or ""}
        if view.sha256
        else {"sha512": sha512.hexdigest()},
        evidence=(view.ref,),
    )
    if declared:
        check_licences(Subject.of_component(component.bom_ref), declared, ctx)
    facts = {
        "name": name,
        "version": version,
        "integrity": [
            "sha512-" + base64.b64encode(sha512.digest()).decode(),
            "sha1-" + base64.b64encode(sha1.digest()).decode(),
        ],
        "bomRef": component.bom_ref,
    }
    return Inspection(
        kind="npm.tarball",
        metadata={"npmTarball": {"name": name, "version": version}},
        components=(component,),
        claims=(make_claim(view, UnitKind.NODE_ENVIRONMENT, "tarball", facts),),
    )


# --- lockfiles ----------------------------------------------------------------------------------


def _entry(
    name: str,
    version: str | None,
    *,
    path: str | None = None,
    resolved: str | None = None,
    integrity: str | None = None,
    optional: bool = False,
    link: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "path": path,
        "resolved": resolved,
        "integrity": integrity,
        "optional": optional,
        "link": link,
    }


def _package_lock(text: str) -> tuple[str, list[dict[str, Any]]]:
    document = json.loads(text)
    entries = []
    packages = document.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            entries.append(
                _entry(
                    name,
                    info.get("version"),
                    path=path,
                    resolved=info.get("resolved"),
                    integrity=info.get("integrity"),
                    optional=bool(info.get("optional")),
                    link=bool(info.get("link")),
                )
            )
        return f"package-lock v{document.get('lockfileVersion')}", entries

    def walk(dependencies: Any, prefix: str) -> None:  # lockfileVersion 1
        for name, info in (dependencies or {}).items():
            if isinstance(info, dict):
                path = f"{prefix}node_modules/{name}"
                entries.append(
                    _entry(
                        name,
                        info.get("version"),
                        path=path,
                        resolved=info.get("resolved"),
                        integrity=info.get("integrity"),
                        optional=bool(info.get("optional")),
                    )
                )
                walk(info.get("dependencies"), f"{path}/")

    walk(document.get("dependencies"), "")
    return "package-lock v1", entries


def _yarn_lock(text: str) -> tuple[str, list[dict[str, Any]]]:
    if "__metadata:" in text:  # Yarn 2+ (Berry): YAML
        document = load_untrusted_yaml(text)
        entries = []
        for key, info in (document or {}).items() if isinstance(document, dict) else []:
            if key == "__metadata" or not isinstance(info, dict):
                continue
            spec = str(key).split(",")[0].strip()
            name = spec[: spec.rfind("@")] if spec.rfind("@") > 0 else spec
            resolution = str(info.get("resolution", ""))
            entries.append(
                _entry(
                    name,
                    str(info.get("version")),
                    resolved=resolution if "@npm:" not in resolution else None,
                )
            )
        return "yarn berry", entries
    entries, current = [], None
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" "):
            spec = line.rstrip(":").split(",")[0].strip().strip('"')
            name = spec[: spec.rfind("@")] if spec.rfind("@") > 0 else spec
            current = _entry(name, None)
            entries.append(current)
        elif current is not None and line.startswith("  ") and not line.startswith("    "):
            key, _, value = line.strip().partition(" ")
            if key in ("version", "resolved", "integrity"):
                current[key] = value.strip().strip('"')
    for entry in entries:
        resolved = entry.get("resolved")
        if isinstance(resolved, str) and "#" in resolved and not entry.get("integrity"):
            entry["integrity"] = None  # a sha1 fragment, not a Subresource Integrity string
    return "yarn v1", entries


def _pnpm_lock(text: str) -> tuple[str, list[dict[str, Any]]]:
    document = load_untrusted_yaml(text)
    entries = []
    packages = mapping(document.get("packages")) if isinstance(document, dict) else {}
    for key, info in packages.items():
        spec = str(key).lstrip("/").split("(")[0]
        at = spec.rfind("@")
        name, version = (spec[:at], spec[at + 1 :]) if at > 0 else (spec, None)
        resolution = (info or {}).get("resolution") if isinstance(info, dict) else {}
        resolution = resolution if isinstance(resolution, dict) else {}
        entries.append(
            _entry(
                name,
                version,
                resolved=resolution.get("tarball") or resolution.get("repo"),
                integrity=resolution.get("integrity"),
                optional=bool((info or {}).get("optional")) if isinstance(info, dict) else False,
            )
        )
    return f"pnpm v{(document or {}).get('lockfileVersion')}" if isinstance(
        document, dict
    ) else "pnpm", entries


def _lockfile(
    parse: Callable[[str], tuple[str, list[dict[str, Any]]]],
) -> Callable[[ArtifactView, Context], Inspection]:
    def handle(view: ArtifactView, ctx: Context) -> Inspection:
        try:
            fmt, entries = parse(read_text(view, 64 << 20))
        except (ValueError, yaml.YAMLError) as exc:
            return Inspection(
                kind="unclassified", metadata={"npmLock": {"unreadable": str(exc)[:200]}}
            )
        remote = [
            {"package": e["name"], "resolved": e["resolved"]}
            for e in entries
            if isinstance(e.get("resolved"), str)
            and not e.get("link")
            and (_REMOTE.match(e["resolved"]) or e["resolved"].startswith(("file:", "link:")))
        ]
        if remote:
            ctx.recorder.fail(
                "node.lockfile.remote-source",
                Subject.of_artifact(view.ref),
                tool=TOOL,
                detail={"packages": remote[:100], "count": len(remote)},
            )
        else:
            ctx.recorder.passed("node.lockfile.remote-source")
        facts = {"format": fmt, "entries": entries}
        return Inspection(
            kind="npm.lockfile",
            metadata={"npmLock": {"format": fmt, "packages": len(entries)}},
            claims=(make_claim(view, UnitKind.NODE_ENVIRONMENT, "lockfile", facts),),
        )

    return handle


def _dispatch(view: ArtifactView) -> Callable[[ArtifactView, Context], Inspection] | None:
    name = name_of(view.ref)
    if name == "package.json":
        return _package_json
    if (
        name in ("package-lock.json", "npm-shrinkwrap.json")
        and "/node_modules/" not in f"/{full_path(view.ref)}"
    ):
        return _lockfile(_package_lock)
    if name == "yarn.lock":
        return _lockfile(_yarn_lock)
    if name == "pnpm-lock.yaml":
        return _lockfile(_pnpm_lock)
    if name.endswith(".tgz") and view.head(2) == b"\x1f\x8b" and _TARBALL.match(name):
        return _tarball
    return None


class NodePackageHandler:
    name = "node-packages"
    version = "1"
    kinds = frozenset({"npm.package-manifest", "npm.tarball", "npm.lockfile"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("npm", 75) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handle = _dispatch(artifact)
        assert handle is not None  # noqa: S101
        try:
            return handle(artifact, ctx)
        except TooLarge as exc:
            return Inspection(kind="unclassified", metadata={"npm": {"skipped": str(exc)}})
        except (ValueError, UnicodeDecodeError) as exc:
            return Inspection(kind="unclassified", metadata={"npm": {"unreadable": str(exc)[:200]}})
