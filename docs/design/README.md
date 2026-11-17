# Design documents

The original project brief, split by topic. Section numbers (§N) are kept from the brief so cross-references stay stable.

| File | Brief sections | Contents |
|---|---|---|
| [01-context-and-threat-model.md](01-context-and-threat-model.md) | §1, §2 | Why the project exists, the low-to-high transfer scenario, threat model and out-of-scope items |
| [02-vision-and-principles.md](02-vision-and-principles.md) | §3, §4 | Module/phase vision, shared core, design principles |
| [03-core-concepts.md](03-core-concepts.md) | §5 | Data model concepts: Transfer Request, Bundle, Artifact, Component, Units, Policy, Finding, Evidence, Receipt |
| [04-artifact-coverage.md](04-artifact-coverage.md) | §6 | Handler interface and per-category coverage (AI, developer environment, general software/infrastructure) |
| [05-model-packages.md](05-model-packages.md) | §7 | `ModelPackage` unit: identity, weights, tokenizer, template, configs, licence, provenance |
| [06-runtime-profiles.md](06-runtime-profiles.md) | §8 | `RuntimeProfile` unit and compatibility checks |
| [07-knowledge-bases-and-agents.md](07-knowledge-bases-and-agents.md) | §9 | `KnowledgeBase` unit, MCP servers, agent hooks/skills/permissions/prompts |
| [08-offline-readiness.md](08-offline-readiness.md) | §10 | Auto-downloads, telemetry, auto-updaters, external endpoints |
| [09-behavioural-verification.md](09-behavioural-verification.md) | §11 | `airlock eval` |
| [10-vm-images.md](10-vm-images.md) | §12 | OpenStack qcow2/raw images, Glance metadata |
| [11-os-patching.md](11-os-patching.md) | §13 | `airlock patch` for AlmaLinux, Ubuntu, Windows |
| [12-transfer-workflow-and-cli.md](12-transfer-workflow-and-cli.md) | §14, §16 | End-to-end workflow, delta bundles, target CLI |
| [13-checks-and-controls.md](13-checks-and-controls.md) | §17, §18 | Check catalogue and NIST SP 800-53 / ITSG-33 control mapping |
| [14-roadmap.md](14-roadmap.md) | §15, §20 | Phases and the initial task list |
| [15-repo-layout.md](15-repo-layout.md) | §19 | Suggested package layout and `examples/` fixtures |
| [16-open-decisions.md](16-open-decisions.md) | §21 | Unresolved decisions |
| [17-core-models.md](17-core-models.md) | new | Core data models, policy schema, keys, logs and interfaces (implemented) |
| [18-bundle-and-verification.md](18-bundle-and-verification.md) | new | Bundle layout, signed statement, pack and verify steps, archive inspection, known limits (implemented) |
| [19-model-packages.md](19-model-packages.md) | new | Model formats, model packages, pickle classification, provenance and trust levels, known limits (implemented) |
| [20-software-and-agents.md](20-software-and-agents.md) | new | Agents and MCP, container images, OS, Python and npm packages, offline resolvability, source, known limits (implemented) |
| [21-scanners-and-basics.md](21-scanners-and-basics.md) | new | Secrets, executables, active content in documents; scanner plugins (ClamAV, Trivy, CISA KEV) and how they are trusted (implemented) |
| [22-data-and-knowledge.md](22-data-and-knowledge.md) | new | Notebooks, datasets, knowledge bases (vector stores, declared corpora, corpus injection and hidden text, embedding-model link), classic ML and MLflow (implemented) |
| [23-offline-and-runtime.md](23-offline-and-runtime.md) | new | Offline readiness (downloads, telemetry, updates, cloud AI, registries, recommended configuration), detected inference stack, runtime profiles, CUDA/driver and policy compatibility (implemented) |
| [24-signatures-and-eval.md](24-signatures-and-eval.md) | new | OpenSSF model signatures verified offline (key, certificate, Sigstore keyless), evaluation sets and `airlock eval` (implemented) |
| [25-reports-and-controls.md](25-reports-and-controls.md) | new | `airlock report`: Markdown, HTML, JSON, CycloneDX 1.6 SBOM/ML-BOM, OSCAL assessment results; the control matrix and rule-to-control mapping (implemented) |
| [26-volumes-and-deltas.md](26-volumes-and-deltas.md) | new | Multi-volume bundles (signed volume index, per-medium checks), delta bundles (carried files resolved from accepted bases), hard-linked payloads (implemented) |
| [27-vendor-trust.md](27-vendor-trust.md) | new | Pinned vendor OpenPGP keys and scopes, the OpenPGP reader, RPM packages and databases, Debian packages, publishers' checksum lists and detached signatures (implemented) |
| [28-package-mirrors.md](28-package-mirrors.md) | new | dnf, apt, PyPI simple, npm storage and Helm mirrors as units: the chain from signed metadata to each package, missing and unlisted content, freshness and rollback against the ledger (implemented) |
| [29-more-ecosystems.md](29-more-ecosystems.md) | new | Java (Maven, Gradle), Go, Rust and .NET: lockfiles resolved against the delivery, lockfile and sidecar hashes, build hooks (implemented) |
| [30-infrastructure-code.md](30-infrastructure-code.md) | new | Kubernetes and Compose posture, unpinned images, Helm/Terraform/Ansible dependencies, Terraform provider hashes, YAML alias budget (implemented) |
| [31-ide-extensions.md](31-ide-extensions.md) | new | VS Code and JetBrains extensions: identity, approved lists, start-up activation, telemetry, proposed APIs, dependencies (implemented) |
| [32-vm-images.md](32-vm-images.md) | new | qcow2, VMDK, VHD, VHDX, raw and ISO headers; incomplete, encrypted, unclean and confused images; OVA/OVF manifests; Glance hashes and signatures; the qemu-img plugin (implemented) |
| [33-patching-and-feeds.md](33-patching-and-feeds.md) | new | `airlock patch inventory/plan/confirm`, OSV, updateinfo, MSRC CVRF and KEV feeds with freshness, emergency plans, Authenticode via osslsigncode (implemented) |
| [34-staging.md](34-staging.md) | new | `airlock stage` and `airlock patch stage`: accepted bundles only, re-hash on copy, target layouts (files, models, PyPI, npm, dnf, apt, OCI, Windows), ledger events, downgrade protection (implemented) |
| [35-zarf-and-hauler.md](35-zarf-and-hauler.md) | new | What Zarf 1.0 and Hauler 2.1 do (sourced), how airlock relates to them, and Zarf packages and Hauler hauls (as built) |

The rule reference, [../rules.md](../rules.md), lists every check with its severity, default outcome and controls. It is generated from the catalogue by `airlock rules`.
