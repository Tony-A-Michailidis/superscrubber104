# 21. The basics: secrets, executables, active content, and scanner plugins

> **Status: implemented** (task 7). Spec: [§17](13-checks-and-controls.md) (secrets, malware, vulnerability matching, scanner plugins), the binaries and documents rows of [§6](04-artifact-coverage.md). Setup guide for operators: [docs/scanners.md](../scanners.md).

Every delivery gets these checks, AI or not. Three are built in and need nothing external; two need a scanner and a database that changes daily, and are optional plugins. The project's guardrail applies throughout: what could not be checked is recorded as *not assessed*, never left out.

## 21.1 Built in

### Secrets

The secrets handler reads **every text artifact**, wherever it sits: project files, archive members, files inside container image layers, wheel and sdist contents, notebooks, datasets. It never classifies a file; it only records findings.

| Kind | Severity | Shape |
|---|---|---|
| Cloud and platform tokens | high | AWS access key ids, GitHub (classic and fine-grained), GitLab, Slack tokens and webhooks, Anthropic, OpenAI, Hugging Face, Google API, Stripe live, npm, PyPI, Azure storage keys |
| Private keys | high | a PEM `BEGIN ... PRIVATE KEY` header **followed by a key body** (on the next line, or after `\n` inside a JSON string, as in service-account files). A bare header, as parsers and docs contain, is not reported |
| JWTs | medium | three base64url segments starting `eyJ` |
| Credentials in URLs | medium | `scheme://user:password@host` |
| Password assignments | medium | `password`, `secret`, `api_key`, `access_token`, ... assigned a quoted literal, ignoring placeholders (`${VAR}`, `<your-key>`, `changeme`, `xxxx`) and values with Shannon entropy below 3 bits per character |

**The secret is never recorded.** A finding carries the type, line and length. Vendors' documented examples (`AKIAIOSFODNN7EXAMPLE`) and obvious dummies are ignored. Hits under test, example, fixture and docs paths, and in files named `example*` or `sample*`, are reported at **low** severity with the context `test or example path`: packages routinely ship dummy keys for their own tests.

Scale: literal triggers are found with `bytes.find` over each 8 MiB block, which is about the speed of memory. Only the lines holding one go through the patterns, and a very long line (minified JSON, one-line data files) only in windows around each trigger. Files are searched up to 256 MiB; beyond that the rest is recorded as not assessed. Validated against real packages: the botocore wheel (96 MB of JSON once unpacked) produces only its documented example passwords, at low severity, and the cryptography sdist only its test and documentation keys, also at low.

### Executables

ELF, PE and Mach-O binaries (including universal binaries, told apart from Java class files) and scripts (by `#!` interpreter, or by extension for PowerShell, batch, VBScript, WSH and HTA) get kinds `executable.*` with format, architecture and word size. For PE files the record also says whether the file is a DLL, its subsystem, whether it is a .NET assembly, and whether it carries an Authenticode signature (recorded as present; verification belongs to Windows patching, 1c). Nothing is executed or loaded.

### Active content in documents

| Format | What is found | Severity |
|---|---|---|
| Office Open XML (`.docx`, `.xlsm`, `.pptx`, ...) | VBA projects; ActiveX; embedded objects; relationships to **external** templates, OLE objects, frames or sub-documents (remote template injection) | medium; external targets high |
| Legacy Office (OLE2) | `_VBA_PROJECT` / `Macros` storage; `\x01Ole10Native` packages; object pools | medium; packages high |
| PDF | `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/SubmitForm`, `/ImportData`, `/GoToE`. Names are decoded (`/J#61vaScript`) and compressed object streams (`/ObjStm`, where modern PDFs keep their dictionaries) are inflated, within bounds | JavaScript and launch high; others medium |
| RTF | `\objdata`, `\objemb` and other embedded-object control words | high |
| SVG | `<script>`, event-handler attributes, `javascript:` URLs | medium |

Rule: `document.active-content`. A document that cannot be read is not assessed.

## 21.2 Scanner plugins

```
src/airlock/scanners/
  base.py      pre-flight (find, hash, pin, version, data age), process runner, Scanner protocol
  clamav.py    clamscan: malware.detected
  trivy.py     trivy image / rootfs / sbom: vuln.component.known
  kev.py       CISA KEV catalogue: kev=true/false on vulnerability findings
  __init__.py  run_scanners(): runs what the policy configures; not assessed for the rest
```

`pack`, `verify` and `inspect` call `run_scanners` after analysis, with the delivery's top-level files on disk (in `pack`, the copies in the bundle payload, which is what gets signed). Each plugin's status (version, binary hash, pinned or not, database version and age, or the reason it could not run) is recorded in `Assessment.plugins`, and the plugin's name, version and database version are the `tool` on every finding it produces.

### Pre-flight

| Step | Failure | Rule | Class |
|---|---|---|---|
| Find the binary (policy `path`, else `PATH`) | not found | `plugin.required.missing` if `required` | policy |
| Hash the binary against `binarySha256` | mismatch | `plugin.integrity.mismatch` | **final** |
| Hash pinned data `files`; refuse unpinned signature files in the database directory | mismatch, missing, extra | `plugin.integrity.mismatch` | **final** |
| Nothing pinned | | `plugin.unpinned` (low) | policy |
| Read the version, compare with `minVersion` | too old | `plugin.version.unsupported` (scanner not run) | policy |
| Read the database age, compare with `maxDbAge` | too old | `plugin.data.stale` (scanner still runs) | policy |
| Run | timeout, bad exit code, unreadable output | `plugin.scan.error`; affected content not assessed | policy |

A scanner that fails its pins is a hash mismatch on a tool that decides what crosses: if it could be waved through, a tampered scanner could wave anything through. That makes `plugin.integrity.mismatch` final, under the owner's rule for integrity failures (doc 17 §17.7).

The process runner uses an argument list (no shell), no standard input, a private working directory as `HOME`/`TEMP`, and an environment stripped to the essentials, with every proxy variable pointing at a closed local port (`127.0.0.1:9`). That is defence in depth for the offline-first rule: airlock itself makes no network calls, and a scanner that tries fails at once instead of leaving the enclave.

### ClamAV

One `clamscan` run per delivery, over a file list of the top-level files, with the policy's signature directory and ClamAV's limits raised to their maximum (4000 MiB). The database version and age come from the CVD/CLD headers (Talos build time), not from `freshclam` state. `Heuristics.Limits.Exceeded.*` results and files over 4000 MiB are not assessed, never clean. A delivery with a detection has `malware.detected` (critical) on that file, with the signature name.

### Trivy

Every finding is placed on the artifact that carries the package:

* each top-level container image (archive or OCI layout) → `trivy image --input`;
* each top-level root filesystem directory → `trivy rootfs`;
* every other component airlock identified with a language purl (pypi, npm, maven, golang, cargo, nuget, gem, composer, ...) and not already inside a scanned image or root filesystem → one CycloneDX SBOM → `trivy sbom`, with findings mapped back through `bom-ref` (or purl).

Always offline: `--skip-db-update --skip-java-db-update --offline-scan --cache-dir <database>`. A root filesystem inside a non-image archive cannot be given to Trivy without unpacking it, so its OS packages are not assessed. Severity is Trivy's; attributes `id`, `severity`, `package`, `ecosystem`, `fixed`, `kev`, `scanner` are there for policy `where` clauses. The finding's subject locator is `package@version`, which keeps waivers stable.

### KEV

The KEV feed is a data-only plugin (no binary) so that it gets the same pinning, age check and status record as a scanner. It loads first; Trivy marks each finding `kev=true` if the vulnerability id or any vendor alias is in the catalogue, `kev=false` if not, `kev=unknown` if no catalogue was loaded.

### Semgrep and Bandit (static analysis)

Static analysis looks at the delivery's **own** code: top-level source files, scripts, agent hooks and skills, MCP servers and model custom code (`modeling_*.py`). Code under `site-packages`, `node_modules` and virtual environments is left out. It is third-party code, covered by the vulnerability scan, and running static analysis over other people's libraries produces noise nobody reviews. Source inside a zipped project (an archive that is not a package or an image) is recorded as not assessed: deliver it unpacked.

* **Semgrep** (`semgrep scan`) runs with the pinned local rules directory as `--config`, `--metrics=off` and `--disable-version-check`. It never fetches rules from a registry, and a rules directory holding an unpinned rule file is refused like an unpinned ClamAV signature. Severity: `ERROR` high, `WARNING` medium, `INFO` low.
* **Bandit** runs its built-in tests over Python files. Severity is Bandit's; a low-confidence result is lowered one step.

Files go to the tools in batches of 200, so command lines stay within Windows' limit. Each result is `sast.finding` on the file and line, with the rule, message, CWE and confidence. When neither tool is configured and the delivery holds first-party source, `sast.finding` is not assessed for the bundle.

### Gaps are explicit

If no malware scanner ran, `malware.detected` is not assessed for the bundle, with the reason "no malware scanner is configured (plugins.clamav)". The same goes for `vuln.component.known`. Defaults make that a warning; `notAssessed: block` on the rule makes scanning mandatory.

`airlock plugins check --policy P` runs the pre-flight only and prints each plugin's state.

## 21.3 Rules

| Rule | Severity | Class |
|---|---|---|
| `plugin.integrity.mismatch` | critical | **final** |
| `malware.detected` | critical | policy (a site may set `overridable: false`) |
| `secret.detected` | high (per type; low under test paths) | policy |
| `vuln.component.known` | from the scanner | policy |
| `sast.finding` | from the analyser (medium by default) | policy |
| `plugin.version.unsupported`, `plugin.scan.error`, `plugin.required.missing` | high | policy |
| `document.active-content` | medium (high for launch actions, JavaScript, external templates, OLE packages) | policy |
| `plugin.data.stale` | medium | policy |
| `plugin.unpinned` | low | policy |

## 21.4 Known limits

- **Not run against the real binaries here.** The ClamAV and Trivy plugins are tested with a stand-in process runner that answers as the tools do (argument lists, output formats, exit codes, database layouts as documented). Running a downloaded scanner binary was not possible in the development environment. Check a real installation with `airlock plugins check` and the steps in [docs/scanners.md](../scanners.md#check-the-integration) before relying on it.
- **Secrets** are found by shape. A credential with no recognisable shape, assigned to an innocuous name, is missed; so is one split across lines or encoded. Git history inside git bundles is not searched (packfiles are compressed objects), and binaries are not searched.
- **Executables:** Authenticode, codesign and ELF signatures are recorded as present or absent, not verified.
- **PDF:** streams other than object streams are not inflated, and encrypted PDFs are not decrypted; obfuscated JavaScript inside an ordinary content stream would be missed by the keyword search (ClamAV covers known samples).
- **ClamAV** reports the archive that contains a detection, not the member.
- **Trivy:** a root filesystem inside a non-image archive is not scanned; lockfile entries without a distribution in the delivery are not scanned (they are reported as unresolvable). Grype and OSV-Scanner are not wrapped yet; the `Scanner` protocol is where they would go.
- **Static analysis** sees only top-level first-party files. Semgrep's native Windows support is limited; run it on Linux, macOS or WSL. Neither tool was run in development (the same stand-in approach as the other scanners).
