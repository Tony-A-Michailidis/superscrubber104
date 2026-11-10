# Checks and control mapping

## 17. Checks (summary)

**Integrity and provenance**
- Hashes, our signature, and upstream signatures/checksums (vendor GPG, Authenticode, VSIX, publisher model hashes, model signatures, Glance).
- Unit completeness: shards, tokenizer, adapters' base model, runtime profile parts, lockfile ↔ wheelhouse, Helm/Terraform dependencies, repo metadata ↔ content.
- Transfer-request conformance: undeclared or missing items.

**Code execution risk**
- Pickle and other code-capable model formats.
- `trust_remote_code`, Keras Lambda layers, TF/ONNX custom ops.
- Package install scripts and build hooks.
- Agent hooks/skills, IDE extension activation and bundled binaries.
- llamafile-style executables.

**Supply chain**
- Approved packages/models (anti-slopsquatting), licence policy (including model licences).
- Vulnerability matching against offline DBs, with DB age.
- Malware scan (ClamAV) and SAST (Semgrep/Bandit) as plugins.

**Configuration and exposure**
- Container hygiene, IaC misconfiguration, MCP tool breadth, agent permission breadth.

**Data**
- Secrets everywhere, including git history, notebook outputs and image layers.
- Optional PII scan of datasets and corpora; document metadata leakage.
- **Prompt injection in corpora, prompts and tool descriptions.**

**Offline readiness:** auto-downloads, telemetry, auto-updaters, external endpoints, cloud AI clients.

**Freshness and replay:** stale feeds, old repo metadata, downgrades, deltas against an unknown base.

**Images:** VM format confusion, backing files, encryption, Glance mismatches.

**Behaviour (1d):** eval comparison within tolerance.

## 18. Evidence and control mapping (starter set; verify each mapping before publishing)

- CM-8 system component inventory → manifest, SBOM/ML-BOM, unit records
- SI-7 software, firmware and information integrity → hashes, signatures, completeness
- SR-3 supply chain controls / SR-4 provenance / SR-11 component authenticity → upstream signatures, publisher references, approved sources, model provenance
- SR-10 inspection of systems or components → static inspection results (models, images, packages)
- CM-7 least functionality → MCP tool lint, agent permissions, container privileges, IDE extension capabilities
- CM-6 configuration settings → IaC/Kubernetes checks, recommended offline configuration
- CM-10 software usage restrictions → licence policy, including model licences and use terms
- CM-11 user-installed software → IDE extensions, developer tools, agent skills
- SC-7 boundary protection / AC-4 information flow enforcement → offline readiness (egress paths), transfer direction, outbound inventory checks
- RA-5 vulnerability monitoring and scanning → vulnerability findings + DB age
- SI-3 malicious code protection → malware scans, code-capable model detection, AV feed age
- SA-11 developer testing and evaluation → SAST results, eval results
- SA-22 unsupported system components → end-of-life runtimes, OS versions, drivers
- SI-2 flaw remediation → patch gap report, before/after inventory, time from advisory to bundle
- CM-3 configuration change control / CM-4 impact analysis → transfer request, approvals, patch plans, supersedence and reboot notes
- AU-10 non-repudiation → signed manifests, approvals, receipts
- MP-5 media transport → chain-of-custody log, media IDs, per-volume hashes

Reports in Markdown/HTML and JSON (OSCAL assessment-results as a stretch goal). Every check that could not run appears as "not assessed".
