# Roadmap: what comes next

Phase 1 is built: `pack`, `verify`, `report`, `approve`, `stage`, `patch`, `eval`, `request` and `model inspect` work end to end, and have been tried on two real deliveries with real scanners. This page lists what is not built yet, so that nothing is implied that the tool does not do. Each item comes from the "known limits" or "not built" section of a design document ([docs/design/](design/README.md), 18 to 35), or from what the real trials found. Within a group, the items most likely to matter for a real AI delivery come first.

Until an item is built, the tool records the gap: a check that could not run is *not assessed*, never left out.

## Trust and verification

| Item | Today | Where |
|---|---|---|
| Cosign verification for Hauler hauls and signed container images | signatures recorded as not assessed | [35](design/35-zarf-and-hauler.md) |
| CMS/PKCS#7 signatures: NuGet packages, JARs, VS Code marketplace extensions | recorded, not verified | [29](design/29-more-ecosystems.md), [31](design/31-ide-extensions.md) |
| Authenticode, codesign and ELF signatures on any executable, and Authenticode results feeding `trust.minimum` | recorded as present or absent; Authenticode verified for Windows updates only | [21](design/21-scanners-and-basics.md), [33](design/33-patching-and-feeds.md) |
| Sigstore: RFC 3161 timestamps, certificate transparency entries, Rekor inclusion proofs, Rekor v2 | the signed entry timestamp from a pinned Rekor key is verified | [24](design/24-signatures-and-eval.md) |
| Offline certificate revocation (pinned CRL bundles) | not checked | [24](design/24-signatures-and-eval.md) |
| Ledger anchoring: counter-signed checkpoints, so a truncated ledger is detectable | truncation of the tail is not detectable from the log alone | [18](design/18-bundle-and-verification.md) |
| A signed policy file, waivers included | its digest is in every assessment: tampering is evident, not prevented | [18](design/18-bundle-and-verification.md) |
| Signed reports from `superscrubber104 report` | inputs are covered by the bundle signature and the receipt; the rendered report is not signed | [25](design/25-reports-and-controls.md) |
| Each scanner's whole environment pinned, not only its launcher (SkillSpector, Semgrep, Bandit) | the launcher is pinned | [21](design/21-scanners-and-basics.md) |
| A SkillSpector report that used an LLM rejected, beyond always passing `--no-llm` | `--no-llm` is forced, last; the report is not checked | [21](design/21-scanners-and-basics.md) |
| Scanner release signatures (Trivy's Sigstore bundle) verified by the tool | the operator verifies them on the connected side | [docs/scanners.md](scanners.md) |

## Coverage: formats and ecosystems

| Item | Today | Where |
|---|---|---|
| Model packages inside archives assembled as units | inventoried, not assembled | [18](design/18-bundle-and-verification.md) |
| The Hugging Face cache layout (`models--org--name/snapshots/…` with symlinks) | links recorded, not followed; use `local_dir` downloads | [19](design/19-model-packages.md) |
| Zarf split packages (`.partNNN`) and packages pulled from OCI registries; chunked hauls (`.zst.001`) | not read | [35](design/35-zarf-and-hauler.md) |
| 7z and RAR contents; zip archives behind a prefix (self-extracting executables, llamafile-style polyglots) | inventoried, contents not inspected | [18](design/18-bundle-and-verification.md) |
| RPM databases in container images (OS packages of RHEL-family images); zstd-compressed layers | recognised, not parsed; zstd layers not assessed | [20](design/20-software-and-agents.md) |
| TensorFlow SavedModel and TFLite custom operators; a real HDF5 reader for Keras; compressed joblib | not inspected, or searched by marker | [19](design/19-model-packages.md) |
| GGUF size checks for every quantisation type; `mmproj` projectors linked to their model | common types checked; projectors form their own packages | [19](design/19-model-packages.md) |
| Maven `pom.xml` resolution; `go.work`, `replace` and Cargo `[patch]`; Conda, Ruby gems, PHP Composer, Swift | inventoried as generic files | [29](design/29-more-ecosystems.md) |
| Parquet column contents (PII, injected text in training data); Arrow; LangChain docstore text; Chroma over 512 MiB; LanceDB, Qdrant, Milvus, Weaviate | recognised, contents not read | [22](design/22-data-and-knowledge.md) |
| Every PDF stream inflated; encrypted PDFs | object streams only | [21](design/21-scanners-and-basics.md) |
| Secrets in git history (packfiles), encoded or split credentials | found by shape in text only | [21](design/21-scanners-and-basics.md) |
| `.tfvars` and Terraform backends; CloudFormation, ARM and Bicep templates | inventoried and scanned as configuration | [30](design/30-infrastructure-code.md) |
| IDE extensions: engine versions against the site's editor; Visual Studio, Eclipse and Neovim plugins | recorded; identified for VS Code and JetBrains only | [31](design/31-ide-extensions.md) |
| VM guests inspected with libguestfs in a sandboxed plugin; VDI, QED and Parallels; expansion limits from virtual size | headers read, never mounted; other formats unclassified | [32](design/32-vm-images.md) |
| Environment markers evaluated against the target runtime profile; templated image names (`${TAG}`) resolved | conditional requirements reported at low severity; templated images skipped | [20](design/20-software-and-agents.md), [23](design/23-offline-and-runtime.md) |

## Scanners and noise

| Item | Today | Where |
|---|---|---|
| Grype and OSV-Scanner plugins; an offline OSV match of the SBOM independent of Trivy | Trivy only | [21](design/21-scanners-and-basics.md) |
| Recommended policy presets for scanner findings (the Semgrep, Bandit and SkillSpector tuning the real trials needed) | documented examples to copy | [docs/scanners.md](scanners.md#tuning), [21](design/21-scanners-and-basics.md) |
| qemu-img and osslsigncode run for real | tested against stand-ins only | [32](design/32-vm-images.md), [33](design/33-patching-and-feeds.md) |
| ClamAV detections named by archive member | the archive that holds the detection is named | [21](design/21-scanners-and-basics.md) |
| SkillSpector runs in parallel (27 folders took 13.5 minutes) | one folder at a time | [21](design/21-scanners-and-basics.md) |
| VEX statements in CycloneDX output | components only | [25](design/25-reports-and-controls.md) |

## Scale and operations

| Item | Today | Where |
|---|---|---|
| Deliveries of millions of files: the inventory spilled to disk while packing | about 5 KiB of memory per file or archive member; flat in file size | [18](design/18-bundle-and-verification.md), [examples/scale/](../examples/scale/README.md) |
| Resumable verification of very large bundles | chunk hashes make it possible; not implemented | [26](design/26-volumes-and-deltas.md) |
| Approvals on read-only media, kept outside the bundle's custody log | appended in place: the bundle must be writable | [18](design/18-bundle-and-verification.md) |
| Media identifiers recorded automatically; filesystem overhead allowed for in volume sizes | recorded by hand in the custody log | [26](design/26-volumes-and-deltas.md) |
| A trusted time source for hosts whose clock cannot be relied on | the local clock, checked against the ledger and bundle times | [18](design/18-bundle-and-verification.md) |

## Patching

| Item | Today | Where |
|---|---|---|
| GPU driver, CUDA and firmware advisory feeds | versions inventoried, no feed matched | [33](design/33-patching-and-feeds.md) |
| Ubuntu OVAL, Red Hat CSAF/VEX; Windows feature updates, Office click-to-run, drivers, WSUS metadata | OSV, dnf `updateinfo`, Microsoft CVRF and CISA KEV | [33](design/33-patching-and-feeds.md) |
| A feed's origin verified in `patch plan`; the plan compared with the inventory | feeds read as given; downgrades refused at staging | [33](design/33-patching-and-feeds.md), [34](design/34-staging.md) |

## Reporting

| Item | Today | Where |
|---|---|---|
| OSCAL assessment plan, assessment subjects and risks | assessment results only | [25](design/25-reports-and-controls.md) |
| A rule for CM-4 (impact analyses) | evidence present, no rule | [25](design/25-reports-and-controls.md) |
| Long reports grouped by rule, with counts | every finding listed; HTML folds long lists | [25](design/25-reports-and-controls.md) |

## New phases

| Phase | Purpose |
|---|---|
| 2: controls as code | Control-mapped gap reports for coding-agent setups on workstations and repositories, with the same policy and evidence model |
| 3: MCP policy gateway | Runtime enforcement between agents and their tool servers: a rule written once is enforced at the gate, on the workstation and at run time |

## Upkeep

* Keep the "known limits" of the design documents in step with what is built. Doc 19 still lists OpenSSF model signatures, target compatibility and custom-code scanning as not yet done, and doc 20 lists other ecosystems as generic only; docs 21, 23, 24 and 29 built them since.
* Release 0.2.0: the changelog's Unreleased section holds the request commands, Zarf completeness, the SkillSpector plugin and the noise fixes from the second trial.
* Re-run [the first real delivery](../examples/demo/real-delivery.md) with the current code; its numbers predate many fixes.
* Add the scanners, SkillSpector included, to the pinned [ai-trial](../examples/ai-trial/README.md) run, as a standing benchmark.
* Pin the GitHub Actions in CI by commit hash rather than by tag.
