"""IDE extensions: VS Code (.vsix and unpacked) and JetBrains plugins. Real files were also
checked: redhat.vscode-yaml 1.14.0 from Open VSX and String Manipulation 9.16.0 from the JetBrains
Marketplace."""

import io
import json
import zipfile
from collections.abc import Mapping
from pathlib import Path

from superscrubber104.core.model import Result
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import write


def _zip(files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data)
    return out.getvalue()


def _vsix(manifest: Mapping[str, object]) -> bytes:
    return _zip(
        {
            "extension.vsixmanifest": b"<PackageManifest/>",
            "extension/package.json": json.dumps(manifest).encode(),
            "extension/dist/extension.js": b"exports.activate = () => {};\n",
        }
    )


def _manifest(name: str, **extra: object) -> dict[str, object]:
    return {
        "publisher": "example",
        "name": name,
        "version": "1.0.0",
        "engines": {"vscode": "^1.80.0"},
        **extra,
    }


def _failing(result, rule: str) -> dict[str, dict]:  # type: ignore[no-untyped-def,type-arg]
    return {
        f.subject.display: dict(f.detail)
        for f in findings_of(result).get(rule, [])
        if f.result is Result.FAIL
    }


def test_vscode_extensions(tmp_path: Path) -> None:
    busy = _manifest(
        "busy",
        activationEvents=["*", "onCommand:busy.run"],
        enabledApiProposals=["terminalDataWriteEvent"],
        dependencies={"@vscode/extension-telemetry": "^0.9.0", "left-pad": "1.3.0"},
        extensionDependencies=["example.base", "example.absent"],
        contributes={
            "configuration": {"properties": {"busy.telemetry.enabled": {"type": "boolean"}}}
        },
    )
    files: dict[str, bytes | str] = {
        "extensions/example.busy-1.0.0.vsix": _vsix(busy),
        "extensions/example.base-1.0.0.vsix": _vsix(
            _manifest("base", activationEvents=["onLanguage:x"])
        ),
        # an unpacked extension directory, as in ~/.vscode/extensions
        "home/.vscode/extensions/example.quiet-2.0.0/package.json": json.dumps(
            _manifest("quiet", version="2.0.0", extensionPack=["example.base"])
        ),
    }
    result = inspect(write(tmp_path / "d", files))
    busy_ref = "extensions/example.busy-1.0.0.vsix!/extension/package.json"
    meta = artifact(result, busy_ref).metadata["ideExtension"]
    assert (meta["id"], meta["startup"], meta["telemetry"]) == ("example.busy", True, True)
    assert _failing(result, "ide.extension.startup")[busy_ref]["events"] == ["*"]
    assert _failing(result, "ide.extension.proposed-api")[busy_ref]["proposals"] == [
        "terminalDataWriteEvent"
    ]
    telemetry = _failing(result, "offline.telemetry.enabled")[busy_ref]
    assert telemetry["fix"] == {"telemetry.telemetryLevel": "off", "busy.telemetry.enabled": False}
    assert _failing(result, "ide.extension.unresolvable") == {
        busy_ref: {"extension": "example.busy", "missing": ["example.absent"]}
    }
    names = {
        c.name
        for c in result.analysis.components
        if c.properties.get("superscrubber104:ide") == "vscode"
    }
    assert names == {"example.busy", "example.base", "example.quiet"}


def test_vscode_allowlist(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "a.vsix": _vsix(_manifest("approved")),
        "b.vsix": _vsix(_manifest("other")),
    }
    policy = "allowlists:\n  vscode: {mode: enforce, entries: ['example.approved==1.0.0']}\n"
    result = inspect(write(tmp_path / "d", files), policy_yaml=policy)
    unapproved = _failing(result, "package.allowlist.unapproved")
    assert list(unapproved) == ["b.vsix!/extension/package.json"]


def test_jetbrains_plugin(tmp_path: Path) -> None:
    plugin_xml = b"""<idea-plugin>
  <id>com.example.tool</id><name>Tool</name><version>3.1</version><vendor>Example</vendor>
  <idea-version since-build="241" until-build="243.*"/>
  <depends>com.intellij.modules.platform</depends>
  <depends>com.example.base</depends>
  <depends optional="true" config-file="extra.xml">com.example.optional</depends>
  <depends>com.example.absent</depends>
</idea-plugin>"""
    base_xml = b"<idea-plugin><id>com.example.base</id><version>1.0</version></idea-plugin>"
    jar = _zip({"META-INF/plugin.xml": plugin_xml, "com/example/Tool.class": b"\xca\xfe\xba\xbe"})
    base = _zip({"META-INF/plugin.xml": base_xml})
    files: dict[str, bytes | str] = {
        "plugins/tool-3.1.zip": _zip({"tool/lib/tool-3.1.jar": jar}),
        "plugins/base.jar": base,
    }
    result = inspect(write(tmp_path / "d", files))
    ref = "plugins/tool-3.1.zip!/tool/lib/tool-3.1.jar!/META-INF/plugin.xml"
    meta = artifact(result, ref).metadata["ideExtension"]
    assert (meta["id"], meta["sinceBuild"], meta["untilBuild"]) == (
        "com.example.tool",
        "241",
        "243.*",
    )
    assert meta["dependsOn"] == ["com.example.base", "com.example.absent"]
    assert _failing(result, "ide.extension.unresolvable")[ref]["missing"] == ["com.example.absent"]
