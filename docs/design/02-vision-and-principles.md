# Vision and design principles

## 3. Vision: one toolkit, shared core

| Phase | Module | One-line purpose |
|---|---|---|
| 1 (MVP) | **airlock pack / verify** | Prepare *any* project delivery (AI and non-AI) for transfer across an air gap. Inventory, hash, scan, sign, bundle, verify on import. |
| 1b | **offline readiness** | Prove the delivery will run disconnected and has no egress paths (telemetry, auto-download, cloud endpoints). |
| 1c | **airlock patch** | Keep disconnected Windows, AlmaLinux and Ubuntu systems patched, with a fast lane for critical, actively exploited vulnerabilities. |
| 1d | **airlock eval** | Behavioural verification: run a pinned evaluation set on both sides of the gap and compare, to detect model substitution or corruption. |
| 1→2 | **evidence / controls mapping** | Every check emits evidence mapped to NIST SP 800-53 / ITSG-33 controls; reports attach to an SA&A. |
| 2 | **controls-as-code for coding agents** | Scan a repo or workstation's agent setup (MCP configs, permissions, hooks, CI). Produce a control-mapped gap report. |
| 3 | **MCP policy gateway** | Local proxy between an agent and its MCP servers. Allowlists, argument rules, hash-chained audit log, suspicious-output detection. |

**Shared core across all modules:** one YAML policy, one evidence/finding model, one signing scheme, one report renderer. A rule such as "this MCP server's shell tool is not allowed" is written once. It is enforced at the airlock, flagged in agent configs (phase 2), and blocked at runtime (phase 3). Design the policy and evidence models first.

## 4. Design principles

- **Offline-first.** No network calls at runtime, ever. The tool must work on a disconnected machine and be vendorable (wheels bundle) so it can cross its own airlock.
- **Handle everything, recognise what it can.** A pluggable handler per artifact type. Anything unrecognised is still inventoried, hashed, signed and generically scanned, and recorded as "unclassified"; it is never silently dropped.
- **Units, not files.** Many assets only work as a set: a model package, a runtime profile, a Python environment, a repo mirror. The airlock understands these units and checks their **completeness and internal consistency**, not just individual file integrity.
- **Evidence-first.** Every check produces a structured finding: control IDs, result, artifact, timestamp, tool and rule versions. Checks that could not run are reported as "not assessed", never omitted.
- **Two layers of trust.** Our signature proves the bundle wasn't altered in transit. Upstream signatures and checksums (vendor GPG, Authenticode, publisher hashes, model signatures, VSIX signatures) prove the content is genuine. Verify and record both.
- **Standards over invention.** CycloneDX (including ML-BOM for models and datasets), package URLs (purl), SLSA/in-toto provenance where sensible, OSCAL for assessment results, NIST 800-53 Rev 5 control IDs (ITSG-33 aligns with 800-53), OpenSSF model signing where publishers use it.
- **Wrap proven scanners, don't reimplement them.** Syft, Grype, Trivy, Semgrep, Bandit, ClamAV, Gitleaks, qemu-img, libguestfs, ModelScan-style tools etc. are optional plugins: used when present, recorded as "not run" when absent. Core functionality must work with zero external scanners.
- **Trust nothing that crosses, including the scanners.** Scanner binaries, rule packs, vulnerability DBs and signing keys are themselves artifacts that cross the airlock pinned and verified. (In 2026 a widely used security scanner was itself compromised in a supply chain attack. Design for that.)
- **Never execute what you inspect.** No unpickling, no importing model code, no running install scripts, no mounting disk images on the host kernel. Inspection is static, or done inside an explicitly sandboxed plugin.
- **Deterministic and reproducible.** Same inputs produce the same manifest and hashes.
- **Scale-aware.** Model packages and images can be hundreds of GB. Stream hashing, avoid loading files into memory, support multi-volume bundles and resumable verification.
- **Minimal dependencies.** Python 3.11+, `cryptography` for ed25519, `pyyaml`, `typer` or `click`. Avoid heavy frameworks; never import ML frameworks just to inspect a model.
- **Public sources only.** Nothing derived from DND or any client environment. Use generic examples. This is an OPSEC and contract guardrail; never relax it.
