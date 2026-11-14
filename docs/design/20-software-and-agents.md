# 20. Agents, containers, packages and source

> **Status: implemented** (task 6). Spec: [§9](07-knowledge-bases-and-agents.md) (MCP and agents), the developer-environment and software rows of [§6](04-artifact-coverage.md), and [§10](08-offline-readiness.md) (offline resolvability). Core models: [17](17-core-models.md). Bundle and archive walk: [18](18-bundle-and-verification.md).

These handlers cover the rest of a project delivery: agent configuration and MCP servers, container images, OS packages, Python and npm packages with their lockfiles, and source code. They follow the same rules as model packages ([19](19-model-packages.md)):

* Handlers report what one file is. Units (container images, Python and Node environments) are formed by assemblers from claim facts, so they also form inside archives.
* Nothing is executed. No `pip`, `npm`, `docker` or `rpm` is called, no install script runs and no layer is mounted. Lockfiles, metadata and manifests are parsed as data.
* Text is the only thing read from a script or a prompt. What a script *does* is judged by pattern, never by running it.

The questions a reviewer needs answered are: *will this install offline on the high side, from exactly these bytes*, and *what can this agent do once it is there*.

## 20.1 Agents and MCP

| Kind | Recognised by | What is checked |
|---|---|---|
| `agent.mcp-config` | `.mcp.json`, `claude_desktop_config.json`, `cline_mcp_settings.json`, `.vscode/mcp.json` (`servers` key), any dot-directory JSON with `mcp` in its name | Each server: launched through a shell (`sh -c`, `cmd /c`, ...); fetched when it starts (`npx`, `pnpx`, `bunx`, `uvx`, `pipx`, `deno`, `docker run`, `uv run --with`); reached over the network (a URL that is not localhost); literal credentials in `env`, `headers` or arguments; Cline `alwaysAllow`/`autoApprove`. The server inventory is recorded. |
| `agent.settings` | `.claude/settings.json`, `.claude/settings.local.json`, `managed-settings.json` | `bypassPermissions`; bare `Bash`, `WebFetch` or `*` allow rules; `enableAllProjectMcpServers`; every hook command, and whether it reaches the network; literal credentials in `env`. |
| `agent.skill`, `agent.command`, `agent.subagent` | `SKILL.md`; Markdown under `.claude/commands/` and `.claude/agents/` | Front matter (`name`, `description`, `allowed-tools`); broad tool grants; the body is scanned as model-facing text. |
| `agent.instructions` | `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `CONVENTIONS.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `copilot-instructions.md`, `.cursor/rules/*`, `*.instructions.md` | Scanned as model-facing text. |
| `agent.system-prompt` | `*system*prompt*` text and template files, `.prompt`, `.prompty` | Scanned as model-facing text. |
| `agent.script` | Scripts under `skills/`, `.claude/hooks/` | Bundled executable code; network access. |
| `agent.mcp-server` | Python importing `mcp` or `fastmcp`; JS/TS importing `@modelcontextprotocol/sdk` or `@modelcontextprotocol/server` | Tools declared (`@mcp.tool`, `.tool()`, `.registerTool()`) with their descriptions; each description scanned as model-facing text; capabilities (below). |

**Model-facing text** (`airlock/text.py`, shared with chat templates) is checked for instruction overrides ("ignore previous instructions"), role reassignment, pseudo-markup aimed at the model (`<IMPORTANT>`), instructions to hide something from the user, requests for secrets (`~/.ssh`, `.env`, API keys), tool-use preconditions ("before using this tool you must ...") and invisible characters (zero-width, bidirectional controls, Unicode tag characters). A tool description is where a poisoned MCP server hides its instructions, so findings name the tool (`server.py#tool run`).

**Capabilities** of an MCP server are what its tools can reach: `shell` (high), `filesystem-write`, `network`, `dynamic-tools` (medium) and `credentials` (low, reading the environment). Each is detected from the code by language-specific patterns; the evidence is the matching line. When the code is in a helper module the scan cannot follow, the tool names still say what the server does (`write_file`, `run_command`, `fetch_url`), and the finding's evidence is those names, located at `#tool names`. A capability is not a defect: the finding exists so that an approver sees, per server, what was granted.

## 20.2 Container images

| Kind | Recognised by |
|---|---|
| `container.image.archive` | A tar (`docker save` or OCI archive) with `manifest.json` or `index.json` + `oci-layout` at its root |
| `container.image.oci-layout` | `index.json` beside an `oci-layout` marker in a directory |
| `container.image.part` | The marker and the `blobs/sha256/*` files of an OCI layout directory (checked through `index.json`) |

The reader follows OCI indexes (nested up to two levels, as multi-platform images are) and Docker `manifest.json`. For every image it verifies:

* every blob the index, manifests and config name is present, with the **size and sha256 its name and descriptor claim**;
* for legacy `docker save` archives, each `layer.tar` against the config's `diff_ids`;
* the config: user (empty, `root`, `0`, `root:*` or `0:*` is root), environment variables with literal credentials, architecture, OS, entrypoint, labels.

The image ID (config digest) is computed from the config content, never taken from a file name. Layers are archives, so the archive walk ([18](18-bundle-and-verification.md)) inspects their contents with every other handler: a model, a wheel or an MCP config inside a layer is found and checked.

**Root filesystems.** A layer, or a rootfs tarball, has absolute symlinks (`bin/sh -> /bin/busybox`) and setuid binaries as a matter of course. When an archive's top level holds at least three of `bin`, `sbin`, `etc`, `usr`, `lib`, `lib64`, `var`, `opt`, `root`, `home`, absolute links are resolved inside the image and are not reported as escapes, and setuid bits are reported at low severity with the context `root filesystem`. Anywhere else both keep their normal severity. Link targets are never followed on the host either way.

**OS packages** inside an image or rootfs: dpkg `status` (Debian, Ubuntu: `pkg:deb`), apk `installed` (Alpine: `pkg:apk`) and `os-release` become SBOM components. RPM databases are recognised and recorded as not parsed.

The `container-image` unit holds every image of an archive or layout, with an `oci` purl (`pkg:oci/<name>@sha256:<digest>`) per image and the layer digests in its attributes.

## 20.3 Python

| Kind | What it is | What is checked |
|---|---|---|
| `python.wheel` | `.whl` | `METADATA` (name, version, requires-python, licence from `License-Expression`, classifiers or `License`); **every file against the wheel's `RECORD`** (content differs, listed but missing, present but not listed); `.pth` files. |
| `python.sdist` | `.tar.gz`, `.zip` named `name-version` | Installing it runs its build backend: always reported. |
| `python.installed` | `*.dist-info/METADATA` in a `site-packages` | Recorded as an installed package of its environment. |
| `python.pth` | `.pth` files | Lines starting with `import` run at every interpreter start. Known names (`distutils-precedence.pth`, `_virtualenv.pth`) are reported at info; anything else is high. |
| `python.virtualenv` | `pyvenv.cfg` | Python version, home, system site packages. |
| `python.lockfile` | `requirements*.txt`, `requirements*.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml` | Each requirement: exact pin, hashes, source (index, URL, VCS, local path), environment markers. Options that point at an index (`--index-url`, `--extra-index-url`, `--find-links` to a URL) are remote sources. |

**Offline resolvability.** The `python-environment` unit, rooted at a lockfile's directory, resolves every locked requirement against the distributions anywhere in the delivery (names canonicalised per PEP 503, versions per PEP 440 with trailing `.0` stripped):

* A pinned requirement with hashes resolves only to a distribution whose sha256 is one of them. A distribution with the right name and version but **a different hash is `python.environment.hash-mismatch`**, reported on the distribution, and final.
* A requirement with no matching distribution is `python.environment.unresolvable`: high when unconditional; low when it has environment markers, which may not apply to the target (`; sys_platform == "win32"`).
* A wheelhouse with wheels for more than one platform is `python.environment.platform-mixed` (low; usually a mistake, sometimes deliberate).

A `site-packages` without a lockfile forms an installed-environment unit instead, listing what is installed. Each distribution is a `pkg:pypi` SBOM component.

## 20.4 Node

| Kind | What it is | What is checked |
|---|---|---|
| `npm.package-manifest` | `package.json` at a package root (nested manifests such as `lib/package.json` with only `type` are ignored) | `preinstall`, `install` and `postinstall` scripts, and `binding.gyp` (an implicit `node-gyp rebuild`). The project's own scripts are low; a dependency's are medium. |
| `npm.tarball` | `.tgz` with gzip magic and `package/package.json` | The same manifest checks; sha512 and sha1 integrity computed in SRI form. |
| `npm.lockfile` | `package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3), `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` | Each entry's name, version, integrity, `resolved` source, optional flag. Git and URL sources are `node.lockfile.remote-source`. |

**Offline resolvability.** The `node-environment` unit resolves each locked entry in this order: the installed package at its `node_modules/...` path with the locked version; a tarball whose integrity equals the lock's; a tarball with the same name and version. A tarball found by name whose integrity differs from the lock is **`node.environment.integrity-mismatch`**, final. Anything else is `node.environment.unresolvable`, low for optional entries (`fsevents` on Linux). Installed `node_modules` carry no integrity of their own, so installed packages are matched by path and version only.

## 20.5 Source

Source files are classified by extension (`source.python`, `source.typescript`, `source.go`, ...) so that they are inventoried as what they are rather than as unclassified. Minified or generated JavaScript and CSS (very long lines, little whitespace) is `source.minified` at info: a reviewer cannot read it, so its provenance matters. Git bundles (`# v2 git bundle`) record their refs. Static analysis, secret scanning and egress checks on source are in [21](21-scanners-and-basics.md) and [23](23-offline-and-runtime.md).

## 20.6 Package allowlists

The same policy section governs Python and npm packages, by name or name and version:

```yaml
allowlists:
  python:
    mode: enforce                  # report: findings at info only
    entries: ["requests==2.32.3", "numpy", "urllib3>=2"]
  npm:
    mode: report
    entries: ["react@^18", "zod", "@scope/thing@2.0.0"]
    file: allowlists/npm.txt       # optional: one entry per line, pinned by hash
    sha256: "..."
```

An exact-version entry matches that version (normalised the same way as the lockfile's); a range or a bare name approves the name. Every locked or installed package outside the list is collected into one `package.allowlist.unapproved` finding per environment.

## 20.7 Rules

| Rule | Severity | Class |
|---|---|---|
| `container.layer.digest-mismatch` | critical | **final** |
| `python.wheel.record-mismatch` | critical | **final** |
| `python.environment.hash-mismatch` | critical | **final** |
| `node.environment.integrity-mismatch` | critical | **final** |
| `mcp.server.shell`, `mcp.server.runtime-fetch`, `mcp.config.credential`, `agent.prompt.injection`, `agent.permissions.broad`, `agent.hook.network`, `container.image.incomplete`, `container.env.credential`, `python.environment.unresolvable`, `python.package.pth-file`, `node.environment.unresolvable`, `package.allowlist.unapproved` | high | policy |
| `mcp.server.remote`, `mcp.server.capability`, `agent.prompt.hidden-characters`, `agent.hook.command`, `container.user.root`, `python.requirements.unpinned`, `python.requirements.remote-source`, `python.package.build-script`, `npm.package.install-script`, `node.lockfile.remote-source` | medium | policy |
| `agent.skill.scripts`, `python.requirements.unhashed`, `python.environment.platform-mixed` | low | policy |
| `source.minified` | info | policy |

The four final rules are hash mismatches against a record that travelled with the content (a manifest digest, a `RECORD`, a lockfile hash, an SRI integrity): the content is not what its own publisher or lockfile says it is. Like the bundle's integrity checks, no policy, waiver or approval changes them. Everything else is a policy matter: an install script, a root user or an MCP server with shell access can be acceptable, and the policy or an approval quorum decides. Severities above are defaults; some findings lower their own severity with context (optional entries, the project's own scripts, known `.pth` files, root filesystems).

New controls: **AC-6** (least privilege: permissions, root user, capabilities), **IA-5** (authenticator management: literal credentials) and **SI-10** (information input validation: model-facing text).

## 20.8 Known limits

- **MCP capabilities** are found per file by pattern, for Python and JavaScript/TypeScript servers only. Helper modules are not followed; tool names fill part of that gap. Servers in other languages are inventoried from client configs but their code is not scanned.
- **Injection detection** is pattern-based. It catches the common forms and every invisible character; a paraphrased instruction passes. A finding is a prompt for review, not proof; no finding is not proof of safety.
- **Container layers** are inspected as separate archives. Whiteouts are not applied, so a file deleted in a later layer is still inspected (the conservative choice). zstd-compressed layers are recognised and reported as not assessed (no zstd in the standard library). Image signatures (cosign, Notation) are not verified yet (phase 1d).
- **RPM databases** are recognised but not parsed: RHEL, AlmaLinux and Fedora images have no OS package components yet.
- **Installed Python packages** are listed but their `RECORD` is not verified (installers rewrite it); only wheels are.
- **Environment markers** are not evaluated against a target; conditional requirements are reported at low severity instead. Target matching arrives with runtime profiles (1b).
- **Node installed packages** cannot be checked against lockfile integrity (npm keeps no hash of an installed package). Ship tarballs, or an offline mirror, for integrity.
- **Vulnerability matching**, SAST, secret scanning and egress checks are not done by these handlers; see [21](21-scanners-and-basics.md) and [23](23-offline-and-runtime.md).
- **Other ecosystems** (Go modules, Cargo, Maven, NuGet, Conda) are inventoried by the generic handler only.
