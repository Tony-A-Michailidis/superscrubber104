# Scanners: ClamAV, Trivy, Semgrep, Bandit, SkillSpector, qemu-img, osslsigncode and the CISA KEV feed

superscrubber104 works without any external scanner. Its own checks cover integrity, model formats, packages, agents, secrets and active content. Two questions need a scanner and a database that changes every day:

| Question | Plugin | What superscrubber104 records without it |
|---|---|---|
| Is there known malware in the delivery? | **ClamAV** (`clamscan`) | `malware.detected`: *not assessed* |
| Do the packages and images have known vulnerabilities? | **Trivy** | `vuln.component.known`: *not assessed* |
| Which of those vulnerabilities are being exploited? | **CISA KEV** catalogue (a data file) | vulnerability findings carry `kev=unknown` |
| Does the delivery's own code have weaknesses? | **Semgrep** and/or **Bandit** | `sast.finding`: *not assessed* (when there is source) |
| Do its agent skills and MCP servers hide instructions or code an agent would act on? | **SkillSpector** (NVIDIA) | `skill.finding`: *not assessed* (when there are skills or MCP servers) |

"Not assessed" is a recorded gap, never a silent pass. By default it is a warning. A site that requires scanning makes it a blocker in the policy:

```yaml
rules:
  - rule: "malware.*"
    disposition: block
    notAssessed: block      # a delivery that was not scanned does not pass
```

This guide covers getting each tool, checking that it is genuine, carrying it to the disconnected side, and configuring superscrubber104 to use it.

## How superscrubber104 treats a scanner

Scanners cross the gap like everything else, and superscrubber104 does not trust them either. Before it lets a scanner see any content, superscrubber104:

1. finds the binary at the path the policy gives. Nothing is picked up from `PATH` unless the policy leaves out `path`.
2. hashes the binary and every pinned database file, and compares them with `binarySha256` and `files`. A mismatch is `plugin.integrity.mismatch`. It is **final**, like a bundle hash mismatch: the scanner does not run, and no approval overrides it.
3. refuses a signature or database file in the scanner's directory that the policy does not pin. A planted allow-list file would otherwise be loaded silently.
4. reads the version (`--version`) and compares it with `minVersion`.
5. reads the database's age from the database itself and compares it with `maxDbAge` (`plugin.data.stale`).

When a scanner runs, it gets an argument list (never a shell), no standard input, a private working directory, and a cleaned environment. Its proxy variables point at a closed local port, so a scanner that tries to reach the network fails at once. The host should have no route out anyway.

Every assessment records each plugin's version, binary hash, database version and age, and whether it was pinned. The evidence states which scanner build and database produced each result.

`superscrubber104 plugins check --policy policy.yaml` runs steps 1 to 5 and reports the result without scanning anything. Run it after every installation or update.

## ClamAV

### Get it (connected side)

| Platform | Source |
|---|---|
| Ubuntu / Debian | `apt install clamav` (provides `clamscan` and `freshclam`) |
| AlmaLinux / RHEL | `dnf install epel-release && dnf install clamav clamav-update` |
| Windows | the installer or portable zip from <https://www.clamav.net/downloads> |
| Any | the official `clamav/clamav` container image |

Verify the download as the publisher describes: distribution packages through the distribution's signed repositories, and release archives from clamav.net through their published GPG signatures. Use a release that has been out for a while; do not take a release on the day it appears.

### Get the signatures (connected side)

ClamAV's databases are `main.cvd`, `daily.cvd` (or `daily.cld`) and `bytecode.cvd`. For an air gap, Cisco's `cvdupdate` tool is the documented way to fetch whole database files for an offline mirror:

```sh
python -m pip install cvdupdate
cvd config set --dbdir ./clamav-db
cvd update
```

`freshclam --datadir ./clamav-db` also works. Either way you end up with a directory of `.cvd` / `.cld` files.

ClamAV checks each CVD's digital signature from Cisco Talos when it loads it. That is the upstream layer of trust. superscrubber104 adds the transit layer (your pins and your bundle signature).

**Your own rules.** ClamAV loads YARA rules (`.yar`, `.yara`) and its own signature formats (`.hdb`, `.ndb`, `.ldb`, ...) from the same directory. Put site rules there and pin them like the CVDs.

### Configure

```yaml
plugins:
  clamav:
    required: true
    path: tools/clamav/clamscan          # clamscan.exe on Windows; relative to the policy file
    database: tools/clamav/db            # always given: superscrubber104 never uses the host's own
    binarySha256: "…"
    files:
      main.cvd: "…"
      daily.cvd: "…"
      bytecode.cvd: "…"
    minVersion: "1.4"
    maxDbAge: 7d
```

superscrubber104 runs, once per delivery:

```
clamscan --database=<database> --no-summary --stdout --max-filesize=4000M --max-scansize=4000M
         --alert-exceeds-max=yes --file-list=<list of top-level files> [args...]
```

The files are given as absolute paths, because clamscan runs in a private working directory. Empty files are not sent: they have no content to scan, and superscrubber104 counts them as clean itself (clamscan would answer "Empty file", not "OK").

ClamAV looks inside archives itself. A file or archive that exceeds ClamAV's own limits (`Heuristics.Limits.Exceeded.*`) is recorded as *not assessed*, not as clean. Files over 4000 MiB, which ClamAV cannot scan, are recorded the same way. In practice these are large model shards, which superscrubber104's own format parsers check for structure and embedded code.

## Trivy

### Get it (connected side)

Download the release archive for your platform from <https://github.com/aquasecurity/trivy/releases>. Each release publishes a checksums file and a Sigstore bundle for it. Verify the bundle with `cosign verify-blob`, using the certificate identity that Trivy's documentation gives for its release workflow. Then check the archive against the checksums file. As with any scanner, prefer a release that has been out for a while, and pin it: scanners and their release pipelines are attractive targets in their own right.

### Get the vulnerability database (connected side)

Trivy's air-gapped mode reads its database from a cache directory and never downloads it:

```sh
trivy image --download-db-only --cache-dir ./trivy-cache
trivy image --download-java-db-only --cache-dir ./trivy-cache   # only if you scan Java
```

The result is `trivy-cache/db/trivy.db` and `trivy-cache/db/metadata.json`, plus `trivy-cache/java-db/` if you fetched the Java database. superscrubber104 reads the database's age from `metadata.json` (`UpdatedAt`).

### Configure

```yaml
plugins:
  trivy:
    required: true
    path: tools/trivy/trivy               # trivy.exe on Windows
    database: tools/trivy/cache           # the --cache-dir above
    binarySha256: "…"
    files:
      db/trivy.db: "…"
      db/metadata.json: "…"
    minVersion: "0.60"
    maxDbAge: 7d
    timeout: 1h
```

What superscrubber104 asks Trivy to scan, so that every finding lands on the file that carries the package:

| Content | Command |
|---|---|
| Each container image (`docker save` or OCI archive, OCI layout directory) | `trivy image --input <image>` |
| Each root filesystem that is a directory of the delivery (has `etc/os-release`) | `trivy rootfs <directory>` |
| Every other package superscrubber104 identified (wheels, sdists, installed Python and npm packages, npm tarballs, ...) | `trivy sbom <CycloneDX file superscrubber104 writes>` |

Each command also gets `--cache-dir <database> --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json --quiet`. Packages appear in the SBOM only when they are in the delivery. When there is nothing at all for Trivy to read (no image, no root filesystem, no delivered package), `vuln.component.known` is recorded as *not assessed* with that reason, never as zero vulnerabilities. A lockfile entry with no distribution beside it is reported as unresolvable instead (it would need the network on the high side).

Severity comes from Trivy's data (`CRITICAL` to `LOW`; `UNKNOWN` is treated as medium). Each finding has the attributes `id`, `severity`, `package`, `ecosystem`, `fixed` (`true` when a fixed version exists) and `kev`. A policy can select on any of these:

```yaml
rules:
  - rule: vuln.component.known          # rules match first to last
    where: { kev: "true" }
    disposition: block
  - rule: vuln.component.known
    where: { fixed: "false" }
    disposition: require-approval
```

## CISA Known Exploited Vulnerabilities

The KEV catalogue is a JSON file published by CISA at <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>. It is data, not a program: superscrubber104 reads it and marks each vulnerability finding `kev=true` or `kev=false` (matching CVE aliases too). Its age is taken from its `dateReleased`.

```yaml
plugins:
  kev:
    path: feeds/known_exploited_vulnerabilities.json
    files: { known_exploited_vulnerabilities.json: "…" }   # relative to the file's directory
    maxDbAge: 2d
```

## Semgrep (static analysis, many languages)

### Get it (connected side)

Semgrep is a Python package: `python -m pip install semgrep==<version>` into a dedicated virtual environment, from a pinned and hash-checked requirements file (`pip install --require-hashes -r semgrep.txt`), then carry that environment across. Semgrep runs best on Linux and macOS; on Windows use WSL.

### Get the rules (connected side)

superscrubber104 only ever gives Semgrep a local rules directory; it never lets it fetch rules from a registry. Pick the rule sets you trust (for example the open-source `semgrep-rules` repository, or your own), copy the `.yml`/`.yaml` files into one directory, and pin every file. A rule file in that directory that the policy does not pin is refused.

### Configure

```yaml
plugins:
  semgrep:
    path: tools/semgrep/bin/semgrep
    database: tools/semgrep/rules          # local rules only
    binarySha256: "…"
    files: { python.yaml: "…", javascript.yaml: "…" }
    minVersion: "1.80"
    timeout: 1h
```

superscrubber104 runs `semgrep scan --config <rules> --json --output <file> --metrics=off --disable-version-check --quiet [args...] <files...>` over the delivery's own top-level source files, scripts, MCP servers, agent hooks and model custom code, in batches. Third-party code under `site-packages`, `node_modules` and virtual environments is left out; the vulnerability scan covers it.

Each finding has the attributes `scanner`, `ruleId` and `category`. `ruleId` is the rule's own id. Semgrep prefixes ids with the directory the rules were loaded from (`home.user.tools.semgrep.rules.python.lang...`); superscrubber104 removes that prefix, so the evidence does not carry the operator's directory and a rule has the same id on every host. `category` comes from the rule's metadata (`security`, `correctness`, `maintainability`, `best-practice`, ...); every Bandit finding is `security`.

### Tuning

A broad rule set run over a real project reports thousands of findings, most of them about tests or code quality. In a real trial (a RAG application with its MCP servers, 337 Semgrep Python rules plus Bandit), 7,074 of 7,809 findings were Bandit's `assert_used` in test files, and most of Semgrep's high-severity findings came from maintainability rules. Tune in the policy, not by deleting findings: an allowed finding is still recorded and counted.

```yaml
rules:                           # rules match first to last
  - rule: sast.finding           # test code does not run in production
    paths: ["**/tests/**", "**/test_*.py", "**/*_test.py", "**/conftest.py"]
    disposition: allow
  - rule: sast.finding           # code quality is not a transfer decision
    where: { category: "[!s]*" } # any category but security
    disposition: warn
```

Security findings then keep the defaults by severity: high blocks, medium needs approval, low warns.

## Bandit (static analysis, Python)

Install `bandit` the same way (a pinned virtual environment) and point the policy at its launcher:

```yaml
plugins:
  bandit:
    path: tools/bandit/bin/bandit
    binarySha256: "…"
    minVersion: "1.7"
    args: ["--skip", "B101"]               # optional: your site's choices
```

superscrubber104 runs `bandit -f json -q -o <file> [args...] <files...>` over the same first-party Python files. Bandit's severity is used, lowered one step when Bandit reports low confidence.

Static-analysis findings are `sast.finding` at the severity the tool reports. Many sites treat them as a review item rather than a blocker:

```yaml
rules:
  - rule: sast.finding
    disposition: require-approval
```

## SkillSpector (agent skills and MCP servers)

[SkillSpector](https://github.com/NVIDIA/SkillSpector) is NVIDIA's open-source scanner for agent skills (Claude Code, Codex, Gemini CLI) and MCP servers: prompt injection, data exfiltration, credential access, excessive agency, tool poisoning, supply-chain risks and YARA signatures, 71 patterns in 17 categories. superscrubber104 runs it as a pinned plugin, static only.

### Get it (connected side)

SkillSpector is a Python package (Python 3.12 or 3.13, for its YARA dependency's wheels). Install a tagged release into its own virtual environment, from a pinned, hash-checked requirements file if you can, and carry that environment across:

```sh
python3.12 -m venv tools/skillspector
tools/skillspector/bin/pip install "git+https://github.com/NVIDIA/SkillSpector.git@v2.13.4"
tools/skillspector/bin/skillspector --version
```

Its patterns and YARA rules are part of the package. A site's own YARA rules can go in a directory of their own, every file pinned (below).

### Configure

```yaml
plugins:
  skillspector:
    path: tools/skillspector/bin/skillspector
    binarySha256: "…"
    minVersion: "2.13"
    timeout: 30m
    # database: tools/skillspector/site-rules   # optional: site YARA rules, each one pinned
    # files: {exfiltration.yar: "…"}
```

What superscrubber104 scans, each as a folder: every agent skill (a folder with a `SKILL.md`), and every MCP server's package root (the nearest folder above the server code with a `package.json` or `pyproject.toml`). A folder inside another one being scanned is covered by it; dependencies (`node_modules`, virtual environments) are left out; skills inside an archive are recorded as not assessed. For each folder:

```
skillspector scan <folder> --format json [--yara-rules-dir <database>] [args...] --no-llm
```

Three things hold whatever `args` says:

* **`--no-llm`, always, and last.** SkillSpector's default mode sends file contents to a hosted model. Nothing leaves the enclave, so only its static analysis runs.
* **The matched text is never recorded.** SkillSpector reports the text each pattern matched, which can be the very secret it found. A `skill.finding` carries the rule id (`P1`, `E1`, `PE3`, ...), category, pattern, line, confidence, explanation and remediation.
* **What it could not finish is not assessed.** SkillSpector reports files it analysed only in part. Each becomes `skill.finding` *not assessed* on that file, with its reason. Its known-vulnerability lookup (SC4) asks OSV.dev, which the sandbox never reaches; it then uses a small built-in list, and the evidence says so. Trivy is the vulnerability scanner.

Severity is SkillSpector's (`CRITICAL` to `LOW`), lowered one step when its confidence is below 0.5. Each finding has the attributes `scanner`, `ruleId` and `category`, for policy `where` clauses:

```yaml
rules:
  - rule: skill.finding
    where: { category: "Prompt Injection" }
    disposition: block
```

## qemu-img (VM disk images)

superscrubber104 reads disk headers itself (doc 32). `qemu-img` adds an independent reading and a consistency check. It is optional: without it, `vm.image.check` is recorded as not assessed whenever the delivery holds a disk image.

Install the distribution package on the connected side (`qemu-utils` on Ubuntu, `qemu-img` on AlmaLinux) or use a static build. Pin the binary:

```yaml
plugins:
  qemu-img:
    path: tools/qemu/qemu-img
    binarySha256: "…"
    minVersion: "7.0"
```

For every top-level disk image superscrubber104 runs `qemu-img info --output=json -U -f <format> <file>` and, for formats qemu can check (qcow2, VHDX), `qemu-img check --output=json -U -f <format> <file>`. The format is always passed explicitly, so qemu never probes it, which is the format-confusion attack doc 32 guards against. `-U` takes no locks. Neither command writes to the image. Any difference from superscrubber104's reading (virtual size, backing file, dirty or corrupt flags, encryption) or any corruption or leak is `vm.image.check`.

`qemu-img` parses untrusted input, like any scanner. Keep it current and pinned.

## osslsigncode (Authenticode, Windows packages)

Verifies Authenticode signatures on Windows updates and binaries from the Linux host (doc 33). Build or install `osslsigncode` 2.x on the connected side and pin it. Export the root certificates you trust (for Microsoft updates, the Microsoft Root Certificate Authority 2010 and 2011, plus the timestamping roots) as PEM into one directory, and pin each file:

```yaml
plugins:
  osslsigncode:
    path: tools/osslsigncode/osslsigncode
    binarySha256: "…"
    database: tools/osslsigncode/roots      # roots.pem, and tsa-roots.pem for timestamps
    files: { roots.pem: "…", tsa-roots.pem: "…" }
```

superscrubber104 runs `osslsigncode verify -in <file> -CAfile roots.pem [-TSA-CAfile tsa-roots.pem]` on every top-level `.msu`, `.cab`, `.msi`, `.exe`, `.dll`, `.sys`, `.msix`, `.appx` and PE file. A digest mismatch is `authenticode.signature.invalid` (final). A signature that does not chain to your roots is `authenticode.signature.untrusted`. No signature is `authenticode.signature.missing`.

Output with no verdict (a crash, a file type it cannot read) is recorded as not assessed. This plugin and `qemu-img` have been tested here with stand-ins for the binaries only: before relying on either, run `superscrubber104 plugins check`, then verify one known-good and one deliberately altered file with your pinned build and confirm the findings.

## Carrying the scanners across

Scanners and their databases are content like any other, so move them with superscrubber104:

1. On the connected side, put the binaries, the ClamAV signature directory, the Trivy cache and the KEV file in one directory, and `superscrubber104 pack` it as its own bundle. Its signature and the receiving ledger then record exactly which scanner kit crossed, and when.
2. On the disconnected side, `superscrubber104 verify` the bundle and install its contents where the policy points.
3. Update the pins in the policy (`superscrubber104 plugins check` prints the binary hash; use `sha256sum` or `Get-FileHash` for the database files) and roll the policy out through your normal change process. Policy changes are logged as `policy.digest.changed`.
4. Run `superscrubber104 plugins check --policy policy.yaml`. It should report every plugin as `ready`.

The very first scanner kit is a bootstrap case: verify it by hand, using the publisher's signatures as above, before you trust it to verify anything else.

Databases change daily and binaries change monthly. Choose `maxDbAge` to match how often you can transfer: a scan against a 30-day-old database misses everything published since. A stale database still runs; `plugin.data.stale` records its age, and the policy decides what that means.

## Check the integration

After configuring, check that each scanner actually reports:

- **ClamAV:** add a site signature for a harmless file to the database directory (an `.hdb` line is `md5:size:name`), pin it, and inspect a directory containing that file. You should get one `malware.detected` finding with your signature's name. Avoid the EICAR test file on workstations: endpoint protection will usually quarantine it before superscrubber104 sees it.
- **Trivy:** inspect a deliberately old image or wheel (for example a release of a popular library with a published CVE) and check that `vuln.component.known` findings appear on that file.

```sh
superscrubber104 plugins check --policy policy.yaml
superscrubber104 model inspect ./test-delivery --policy policy.yaml
```
