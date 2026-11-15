"""IDE extensions: VS Code (``.vsix`` and unpacked extension directories) and JetBrains plugins.

Extensions run with the developer's rights inside the workspace, often with bundled native
binaries, and many phone home. Each is identified so it can be approved by name and version
(``allowlists.vscode``, ``allowlists.jetbrains``), and these are recorded:

* when it activates: on every start (``*``, ``onStartupFinished``) is ``ide.extension.startup``;
* telemetry (a telemetry library or settings) as ``offline.telemetry.enabled``, with the setting
  that turns it off;
* proposed (unstable) VS Code APIs, which only work on Insiders builds:
  ``ide.extension.proposed-api``;
* what it depends on: extension dependencies and packs, plugin ``<depends>``. Whether those are in
  the delivery is decided once every extension is known (``ide.extension.unresolvable``).

A ``.vsix`` is a zip; its ``extension/package.json`` is found and read as an archive member, and
its native binaries are inspected by the executables handler like any other member. JetBrains
plugins are recognised by ``META-INF/plugin.xml`` inside the plugin jar.
"""

import re
import xml.etree.ElementTree as ET
from collections.abc import Sequence

from airlock import __version__
from airlock.checks.allowlists import check_allowlist
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import (
    Artifact,
    Component,
    ComponentType,
    Severity,
    Subject,
    ToolRef,
)
from airlock.handlers.common import TooLarge, full_path, mapping, name_of, read_bytes, read_json

TOOL = ToolRef("airlock.ide", __version__)
_TELEMETRY_LIBS = (
    "@vscode/extension-telemetry",
    "vscode-extension-telemetry",
    "applicationinsights",
    "@microsoft/1ds-core-js",
    "posthog",
    "@sentry/",
    "@redhat-developer/vscode-redhat-telemetry",
)
_STARTUP = frozenset({"*", "onStartupFinished"})
_PLATFORM_MODULES = re.compile(r"^(com\.intellij\.modules\.|com\.intellij$)")


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref)
    path = full_path(view.ref)
    if name == "package.json" and view.size <= 16 << 20:
        head = view.head(1 << 16)
        if b'"engines"' in head and b'"vscode"' in head and b'"publisher"' in head:
            return "ide.vscode-extension"
    if (
        name == "plugin.xml"
        and path.endswith("META-INF/plugin.xml")
        and b"<idea-plugin" in view.head(4096)
    ):
        return "ide.jetbrains-plugin"
    return None


class IdeExtensionHandler:
    name = "ide"
    version = "1"
    kinds = frozenset({"ide.vscode-extension", "ide.jetbrains-plugin"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 80) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        if _kind(artifact) == "ide.vscode-extension":
            return self._vscode(artifact, ctx)
        return self._jetbrains(artifact, ctx)

    def _vscode(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            manifest = mapping(read_json(view))
        except (TooLarge, ValueError) as exc:
            return Inspection(
                kind="ide.vscode-extension", metadata={"ideExtension": {"error": str(exc)[:300]}}
            )
        publisher, name = str(manifest.get("publisher", "")), str(manifest.get("name", ""))
        identifier = f"{publisher}.{name}".lower()
        version = str(manifest.get("version", ""))
        subject = Subject.of_artifact(view.ref)
        activation = [str(e) for e in manifest.get("activationEvents") or [] if isinstance(e, str)]
        startup = sorted(_STARTUP.intersection(activation))
        if startup:
            ctx.recorder.fail(
                "ide.extension.startup",
                subject,
                tool=TOOL,
                detail={"extension": identifier, "events": startup},
            )
        proposed = [str(p) for p in manifest.get("enabledApiProposals") or []]
        if proposed:
            ctx.recorder.fail(
                "ide.extension.proposed-api",
                subject,
                tool=TOOL,
                detail={"extension": identifier, "proposals": proposed[:50]},
            )
        libraries = sorted(
            lib for lib in mapping(manifest.get("dependencies")) if lib.startswith(_TELEMETRY_LIBS)
        )
        settings = sorted(
            key
            for block in _configuration_blocks(manifest)
            for key in mapping(block.get("properties"))
            if "telemetry" in key.lower()
        )
        if libraries or settings:
            ctx.recorder.fail(
                "offline.telemetry.enabled",
                subject,
                tool=TOOL,
                detail={
                    "what": f"extension {identifier} sends telemetry",
                    "libraries": libraries,
                    "settings": settings,
                    "fix": {"telemetry.telemetryLevel": "off", **{s: False for s in settings}},
                },
                attributes={"impact": "phones-home", "what": "extension telemetry"},
                severity=Severity.LOW,
                discriminator=f"extension:{identifier}",
            )
        check_allowlist(ctx, "vscode", [(identifier, version)], subject)
        dependencies = [str(d).lower() for d in manifest.get("extensionDependencies") or []]
        pack = [str(d).lower() for d in manifest.get("extensionPack") or []]
        engine = str(mapping(manifest.get("engines")).get("vscode", ""))
        part = Component(
            bom_ref=f"vscode:{identifier}@{version}#{view.sha256 or full_path(view.ref)}"[:300],
            type=ComponentType.APPLICATION,
            name=identifier,
            version=version,
            supplier=publisher or None,
            hashes={"sha256": view.sha256} if view.sha256 else {},
            evidence=(view.ref,),
            properties={"airlock:ide": "vscode", "airlock:vscode-engine": engine},
        )
        summary = {
            "ide": "vscode",
            "id": identifier,
            "version": version,
            "engine": engine,
            "activation": activation[:50],
            "startup": bool(startup),
            "main": manifest.get("main"),
            "browser": manifest.get("browser"),
            "dependsOn": [*dependencies, *pack],
            "proposedApi": proposed[:50],
            "telemetry": bool(libraries or settings),
            "untrustedWorkspaces": mapping(
                mapping(manifest.get("capabilities")).get("untrustedWorkspaces")
            ).get("supported"),
        }
        return Inspection(
            kind="ide.vscode-extension", metadata={"ideExtension": summary}, components=(part,)
        )

    def _jetbrains(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            root = ET.fromstring(read_bytes(view, 4 << 20))  # noqa: S314 - see the import
        except (ET.ParseError, TooLarge) as exc:
            return Inspection(
                kind="ide.jetbrains-plugin", metadata={"ideExtension": {"error": str(exc)[:300]}}
            )
        identifier = (root.findtext("id") or root.findtext("name") or "").strip()
        version = (root.findtext("version") or "").strip()
        vendor = (root.findtext("vendor") or "").strip() or None
        build = root.find("idea-version")
        depends = []
        for element in root.findall("depends"):
            target = (element.text or "").strip()
            if target and element.get("optional") != "true" and not _PLATFORM_MODULES.match(target):
                depends.append(target)
        subject = Subject.of_artifact(view.ref)
        check_allowlist(ctx, "jetbrains", [(identifier, version)], subject)
        part = Component(
            bom_ref=f"jetbrains:{identifier}@{version}#{full_path(view.ref)}"[:300],
            type=ComponentType.APPLICATION,
            name=identifier,
            version=version or None,
            supplier=vendor,
            evidence=(view.ref,),
            properties={"airlock:ide": "jetbrains"},
        )
        summary = {
            "ide": "jetbrains",
            "id": identifier,
            "version": version,
            "sinceBuild": build.get("since-build") if build is not None else None,
            "untilBuild": build.get("until-build") if build is not None else None,
            "dependsOn": depends,
        }
        return Inspection(
            kind="ide.jetbrains-plugin", metadata={"ideExtension": summary}, components=(part,)
        )


def _configuration_blocks(manifest: dict[str, object]) -> list[dict[str, object]]:
    configuration = mapping(manifest.get("contributes")).get("configuration")
    if isinstance(configuration, list):
        return [mapping(c) for c in configuration]
    return [mapping(configuration)]


def check_extension_dependencies(artifacts: Sequence[Artifact], ctx: Context) -> None:
    """Every extension or plugin an extension needs must be in the delivery too."""
    extensions = [
        (a, m) for a in artifacts if isinstance(m := a.metadata.get("ideExtension"), dict)
    ]
    present = {(str(m.get("ide")), str(m.get("id")).lower()) for _, m in extensions}
    for artifact, meta in extensions:
        ide = str(meta.get("ide"))
        depends = meta.get("dependsOn")
        needed = [d for d in depends if isinstance(d, str)] if isinstance(depends, list) else []
        missing = [d for d in needed if (ide, d.lower()) not in present]
        if missing:
            ctx.recorder.fail(
                "ide.extension.unresolvable",
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                detail={"extension": meta.get("id"), "missing": missing},
            )
        elif needed:
            ctx.recorder.passed("ide.extension.unresolvable")
