# 31. IDE extensions

> **Status: implemented.** Spec: [§4](04-artifact-coverage.md) (developer tooling), [§1](01-context-and-threat-model.md) (local coding-assistant set-ups).

Developers on the high side need their editors and AI coding assistants. Extensions run with the developer's rights inside the workspace and often bundle native binaries. Many also phone home. Each is identified so a site can keep an approved list, and what it will do is recorded.

## 31.1 What is read

| Editor | Recognised by | Identity |
|---|---|---|
| VS Code (and Open VSX builds such as VSCodium) | a `package.json` with `engines.vscode` and `publisher`: inside a `.vsix` (`extension/package.json`, found as an archive member) or in an unpacked extension directory (`~/.vscode/extensions/<id>-<version>/`) | `publisher.name` (lower case), `version` |
| JetBrains IDEs | `META-INF/plugin.xml` with `<idea-plugin>`: inside the plugin jar, itself usually inside the plugin zip | `<id>` (or `<name>`), `<version>`, `<vendor>` |

Native binaries in either are inspected by the executables handler like any other archive member ([21](21-scanners-and-basics.md)). Their JavaScript and Java are third-party code: the secret and SAST plugins see it, and the offline checks on first-party code do not.

## 31.2 Checks

| Rule | Severity | When |
|---|---|---|
| `ide.extension.startup` | info | activation on `*` or `onStartupFinished`: it runs whether or not it is used |
| `ide.extension.proposed-api` | low | `enabledApiProposals`: only works on Insiders builds or with flags |
| `offline.telemetry.enabled` | low | a telemetry library in its `dependencies`, or settings with `telemetry` in their name. The fix lists `telemetry.telemetryLevel: off` and each such setting set to `false` |
| `ide.extension.unresolvable` | medium | `extensionDependencies`, `extensionPack` or a required plugin `<depends>` (not optional, not a `com.intellij.modules.*` platform module) is not in the delivery. Decided in `analysis.finish`, once every extension is known |
| `package.allowlist.unapproved` | per policy | `allowlists.vscode` or `allowlists.jetbrains` is set and the extension is not on it (entries `publisher.name` or `publisher.name==1.2.3`) |

```yaml
allowlists:
  vscode: { mode: enforce, entries: ["ms-python.python==2024.14.0", "redhat.vscode-yaml"] }
  jetbrains: { mode: report, file: allow/jetbrains.txt, sha256: "…" }
```

Each extension becomes an SBOM component (type application, the publisher as supplier, with `airlock:ide` and the VS Code engine range as properties). There is no purl type for editor extensions, so none is invented.

Metadata kept per extension: engine range or build range, activation events, entry points (`main`, `browser`), dependencies and packs, proposed APIs, telemetry, and whether it declares support for untrusted workspaces.

## 31.3 Validation and limits

Checked against `redhat.vscode-yaml` 1.14.0 from Open VSX (telemetry found through `redhat.telemetry.enabled`) and String Manipulation 9.16.0 from the JetBrains Marketplace (plugin.xml read through zip → jar → member). Tests: `tests/test_ide.py`.

Not done:

* Marketplace signatures (`.signature.p7s` in a separate `.sigzip`) are not verified, for the same reason as NuGet's ([29.6](29-more-ecosystems.md)).
* Engine and build ranges are recorded, not compared with the high side's editor version. A `runtime`-style compatibility rule could do that when the site states its versions.
* Visual Studio (`.vsix` with `extension.vsixmanifest` only), Eclipse plugins and Neovim plugins are inventoried, not identified.
