# Roadmap: what comes next

Phase 1 is built: `pack`, `verify`, `report`, `approve`, `stage`, `patch`, `eval`, `request` and `model inspect` work end to end, and have been tried on two real deliveries with real scanners. This page lists everything that is not built yet, so that nothing is implied that the tool does not do. Each item comes from the "known limits" or "not built" section of a design document ([docs/design/](design/README.md), 18 to 35), or from what the real trials found. Within a group, the items most likely to matter for a real AI delivery come first. The last section lists what the guardrails rule out, and why.

Until an item is built, the tool records the gap: a check that could not run is *not assessed*, never left out.

## Trust and verification

| Item | Today | Where |
|---|---|---|
| Cosign verification for Hauler hauls and signed container images | signatures recorded as not assessed | [35](design/35-zarf-and-hauler.md) |
| CMS/PKCS#7 signatures: NuGet packages, JARs, VS Code marketplace extensions | recorded, not verified | [29](design/29-more-ecosystems.md), [31](design/31-ide-extensions.md) |
| Authenticode, codesign and ELF signatures on any executable, and Authenticode results feeding `trust.minimum` | recorded as present or absent; Authenticode verified for Windows updates only, as findings | [21](design/21-scanners-and-basics.md), [33](design/33-patching-and-feeds.md) |
| Sigstore: RFC 3161 timestamps, certificate transparency entries, Rekor inclusion proofs against a checkpoint, Rekor v2 | the signed entry timestamp from a pinned Rekor key is verified | [24](design/24-signatures-and-eval.md) |
| Offline certificate revocation (pinned CRL bundles) | not checked | [24](design/24-signatures-and-eval.md) |
| Model signature coverage checked against every file in the model's directory | checked against the files assigned to the model package | [24](design/24-signatures-and-eval.md) |
| Ledger anchoring: counter-signed checkpoints, so a truncated ledger or custody log is detectable | truncation of the tail is not detectable from the log alone | [18](design/18-bundle-and-verification.md) |
| A signed policy file, waivers included | its digest is in every assessment: tampering is evident, not prevented | [18](design/18-bundle-and-verification.md) |
| Signed reports from `superscrubber104 report` | inputs are covered by the bundle signature and the receipt; the rendered report is not signed | [25](design/25-reports-and-controls.md) |
| A trusted time source for hosts whose clock cannot be relied on | the local clock, checked against the ledger and bundle times | [18](design/18-bundle-and-verification.md) |
| Each scanner's whole environment pinned, not only its launcher (SkillSpector, Semgrep, Bandit) | the launcher is pinned | [21](design/21-scanners-and-basics.md) |
| A SkillSpector report that used an LLM rejected, beyond always passing `--no-llm` | `--no-llm` is forced, last; the report is not checked | [21](design/21-scanners-and-basics.md) |
| Scanner release signatures (Trivy's Sigstore bundle) verified by the tool | the operator verifies them on the connected side | [docs/scanners.md](scanners.md) |
| Installed Python packages checked against their wheel's `RECORD` when the wheel is also delivered | installed packages are listed, their `RECORD` not verified (installers rewrite it) | [20](design/20-software-and-agents.md) |
| Installed Node packages checked against a delivered tarball or mirror | matched by path and version; npm keeps no hash of an installed package | [20](design/20-software-and-agents.md) |
| Patch bundles' dependency closure verified offline | resolved on the connected side by the package manager | [33](design/33-patching-and-feeds.md) |

## Coverage: archives and containers

| Item | Today | Where |
|---|---|---|
| Model packages inside archives assembled as units; download records, Ollama blobs and ONNX external data resolved inside archives | inventoried, not assembled; those checks not assessed | [18](design/18-bundle-and-verification.md), [19](design/19-model-packages.md) |
| Zarf split packages (`.partNNN`) and packages pulled from OCI registries; chunked hauls (`.zst.001`) | not read | [35](design/35-zarf-and-hauler.md) |
| 7z and RAR contents | inventoried, contents not inspected | [18](design/18-bundle-and-verification.md) |
| zip archives behind a prefix (self-extracting executables, llamafile-style polyglots) | detection reads leading bytes; not opened | [18](design/18-bundle-and-verification.md) |
| zstd without the optional extra before Python 3.14 | not assessed, with advice to install `superscrubber104[zstd]` | [18](design/18-bundle-and-verification.md) |
| RPM databases in container images (OS packages of RHEL-family images, into the SBOM and the vulnerability scan) | recognised, not parsed | [20](design/20-software-and-agents.md) |
| zstd-compressed container layers | recognised, not assessed | [20](design/20-software-and-agents.md) |
| An optional mode that applies layer whiteouts, to inspect the image as it runs | every layer inspected separately, deleted files included (the conservative default) | [20](design/20-software-and-agents.md) |
| A root filesystem inside a non-image archive scanned by Trivy | its OS packages are not assessed | [21](design/21-scanners-and-basics.md) |

## Coverage: models

| Item | Today | Where |
|---|---|---|
| The Hugging Face cache layout (`models--org--name/snapshots/…` with symlinks into `blobs/`) | links recorded, not followed; use `local_dir` downloads | [19](design/19-model-packages.md) |
| TensorFlow SavedModel and TFLite custom operators | reported as not inspected | [19](design/19-model-packages.md) |
| A real HDF5 reader for Keras `.h5` (layer names, Lambda layers by name) | searched by marker | [19](design/19-model-packages.md) |
| Compressed joblib; the rest of an uncompressed joblib stream after its first array | not assessed | [19](design/19-model-packages.md) |
| GGUF tensor sizes for every quantisation type | common fixed-layout types checked; others listed | [19](design/19-model-packages.md) |
| Multimodal models: `mmproj` projectors linked to their model, and whether an architecture needs one | projectors recorded and form their own packages | [19](design/19-model-packages.md) |
| Conversion history beyond what safetensors `__metadata__` records | limited to that metadata | [19](design/19-model-packages.md) |
| Licence identification by text comparison, not only distinctive phrases and identifiers | anything else is reported as unidentified | [19](design/19-model-packages.md) |
| MLflow flavours other than `python_function`; custom code beyond `MLmodel` | recorded, not checked further | [22](design/22-data-and-knowledge.md) |
| Semantic comparison in `eval`, not only character-level similarity | `difflib` ratio of whitespace-normalised outputs | [24](design/24-signatures-and-eval.md) |
| `eval` runtimes sandboxed beyond their closed network | closed proxies; run evaluations on an isolated host | [24](design/24-signatures-and-eval.md) |

## Coverage: software ecosystems and mirrors

| Item | Today | Where |
|---|---|---|
| Maven `pom.xml` resolution (parents, BOMs, properties, ranges) | not resolved without a lockfile or verification metadata | [29](design/29-more-ecosystems.md) |
| `go.work`, `replace` directives outside the delivery, Cargo `[patch]` sections | not interpreted | [29](design/29-more-ecosystems.md) |
| Conda, Ruby gems, PHP Composer, Swift | inventoried as generic files | [29](design/29-more-ecosystems.md) |
| Environment markers evaluated against the target runtime profile | conditional requirements reported at low severity | [20](design/20-software-and-agents.md) |
| dnf mirrors: `filelists`, `other` and `modules.yaml` (RHEL modularity) read; `xml:base` followed | hashes checked against `repomd.xml`, contents not read; `xml:base` not followed | [28](design/28-package-mirrors.md) |
| apt mirrors: `Contents`, `i18n` and `by-hash` read | not read | [28](design/28-package-mirrors.md) |
| MCP server capabilities followed into helper modules, and found in servers written in other languages | per file, by pattern, Python and JavaScript/TypeScript only; tool names fill part of the gap | [20](design/20-software-and-agents.md) |

## Coverage: data, documents and agents

| Item | Today | Where |
|---|---|---|
| Parquet column contents (PII, injected text in training data) | footers read, values not | [22](design/22-data-and-knowledge.md) |
| Arrow files parsed (row counts) | recognised, not parsed | [22](design/22-data-and-knowledge.md) |
| LangChain docstore text extracted | the pickle is flagged, its text not read | [22](design/22-data-and-knowledge.md) |
| Chroma databases over 512 MiB; LanceDB, Qdrant, Milvus, Weaviate, pgvector, Neo4j contents | not opened, or not read | [22](design/22-data-and-knowledge.md) |
| Corpus folders found without being declared | scanned when declared in the request or with `--corpus` | [22](design/22-data-and-knowledge.md) |
| Text in images (OCR) and in PDF fonts without a text map | not scanned | [22](design/22-data-and-knowledge.md) |
| Embedding models matched to knowledge bases by more than name | by name; record the pairing in the request | [22](design/22-data-and-knowledge.md) |
| Every PDF stream inflated; encrypted PDFs | object streams only | [21](design/21-scanners-and-basics.md) |
| Secrets in git history (packfiles), in binaries, and encoded or split credentials | found by shape in text only | [21](design/21-scanners-and-basics.md) |
| Prompt injection found by meaning (a paraphrased instruction), with a pinned local model | by pattern, plus every invisible character | [20](design/20-software-and-agents.md) |

## Coverage: infrastructure, IDEs and VM images

| Item | Today | Where |
|---|---|---|
| Helm templates, Kustomize overlays and Jsonnet rendered offline before inspection | not rendered; templated images skipped | [30](design/30-infrastructure-code.md), [23](design/23-offline-and-runtime.md) |
| `.tfvars` and Terraform `backend` settings | not read | [30](design/30-infrastructure-code.md) |
| CloudFormation, ARM and Bicep templates | inventoried and scanned as configuration | [30](design/30-infrastructure-code.md) |
| IDE extensions: engine and build ranges compared with the site's editor versions | recorded | [31](design/31-ide-extensions.md) |
| Visual Studio, Eclipse and Neovim plugins identified | inventoried, not identified | [31](design/31-ide-extensions.md) |
| VM guests inspected with libguestfs in a sandboxed plugin: guest OS, packages into the SBOM, users, keys, cloud-init, models | headers read, never mounted | [32](design/32-vm-images.md) |
| VDI, QED and Parallels images; compressed qcow2 clusters | unclassified; clusters not decompressed | [32](design/32-vm-images.md) |
| Expansion limits for compressed exports based on virtual size | the archive limits apply | [32](design/32-vm-images.md) |

## Offline readiness and runtime

| Item | Today | Where |
|---|---|---|
| Downloads behind helper functions and URLs assembled at run time | found by pattern; third-party code deliberately not read | [23](design/23-offline-and-runtime.md) |
| Hub ids matched to delivered models by more than name and path | by name | [23](design/23-offline-and-runtime.md) |
| A driver table for Windows | Linux only | [23](design/23-offline-and-runtime.md) |
| GPU compute capability, GPU memory and TensorRT engine targets checked against the profile | recorded from the profile, not checked | [23](design/23-offline-and-runtime.md) |
| Image versions when the tag gives none (`latest`): from the image's labels or contents | taken from the tag | [23](design/23-offline-and-runtime.md) |

## Accuracy and noise

| Item | Today | Where |
|---|---|---|
| Recommended policy presets for scanner findings (the Semgrep, Bandit and SkillSpector tuning the real trials needed) | documented examples to copy | [docs/scanners.md](scanners.md#tuning), [21](design/21-scanners-and-basics.md) |
| Cloud AI endpoints in comments and test files reported at low severity | reported at full severity | [first real delivery](../examples/demo/real-delivery.md) |
| Documentation examples in installed libraries' docstrings (urllib, pydantic) not reported as secrets | reported as medium-severity secrets | [first real delivery](../examples/demo/real-delivery.md) |
| Model packages named from their download record (the repository they came from), not the config's `_name_or_path` | MiniLM is named after `nreimers/…` in its config | [first real delivery](../examples/demo/real-delivery.md) |

## Scanners

| Item | Today | Where |
|---|---|---|
| Grype and OSV-Scanner plugins; an offline OSV match of the SBOM independent of Trivy | Trivy only | [21](design/21-scanners-and-basics.md) |
| SkillSpector's SC4 lookup fed from a local, pinned OSV copy | offline, it uses only its small built-in list | [21](design/21-scanners-and-basics.md) |
| qemu-img and osslsigncode run for real | tested against stand-ins only | [32](design/32-vm-images.md), [33](design/33-patching-and-feeds.md) |
| ClamAV detections named by archive member | the archive that holds the detection is named | [21](design/21-scanners-and-basics.md) |
| SkillSpector runs in parallel (27 folders took 13.5 minutes) | one folder at a time | [21](design/21-scanners-and-basics.md) |
| Static analysis of source inside archives and below the top level of packages | top-level first-party files; zipped projects not assessed | [21](design/21-scanners-and-basics.md) |
| Semgrep on Windows | run it on Linux, macOS or WSL | [21](design/21-scanners-and-basics.md) |

## Scale and operations

| Item | Today | Where |
|---|---|---|
| Deliveries of millions of files: the inventory spilled to disk while packing | about 5 KiB of memory per file or archive member; flat in file size | [18](design/18-bundle-and-verification.md), [examples/scale/](../examples/scale/README.md) |
| Packing without a second copy where the filesystem supports it (reflinks) | `pack` copies; `--link` hard-links | [18](design/18-bundle-and-verification.md) |
| Resumable verification of very large bundles | chunk hashes make it possible; not implemented | [26](design/26-volumes-and-deltas.md) |
| Verification of split files without reassembling them in scratch space | needs room for the largest split file | [26](design/26-volumes-and-deltas.md) |
| Filesystem overhead allowed for in volume sizes | sizes are exact content bytes: leave a margin | [26](design/26-volumes-and-deltas.md) |
| Media identifiers (serial numbers, labels) recorded automatically | recorded by hand in the custody log | [26](design/26-volumes-and-deltas.md) |
| Approvals on read-only media, kept outside the bundle's custody log | appended in place: the bundle must be writable | [18](design/18-bundle-and-verification.md) |

## Patching and staging

| Item | Today | Where |
|---|---|---|
| GPU driver, CUDA and firmware advisory feeds | versions inventoried, no feed matched | [33](design/33-patching-and-feeds.md) |
| Ubuntu OVAL and Red Hat CSAF/VEX | OSV covers the same advisories | [33](design/33-patching-and-feeds.md) |
| Windows feature updates, Office click-to-run, driver updates, WSUS metadata | cumulative updates and supersedence (the KB model) | [33](design/33-patching-and-feeds.md) |
| A feed's origin verified in `patch plan` | feeds read as given | [33](design/33-patching-and-feeds.md) |
| The patch plan compared with the bundle's packages | downgrades refused at staging | [33](design/33-patching-and-feeds.md), [34](design/34-staging.md) |
| Two versions of one OS package in a patch bundle: only the newest staged, or a policy rule for it | the older are `package.superseded` (info); both staged | [33](design/33-patching-and-feeds.md) |
| Repository metadata generated for loose RPMs and debs (`createrepo_c`, reprepro) as a pinned plugin | the stager prints the command to run | [34](design/34-staging.md) |
| A Hugging Face cache layout as a `models` staging target | the delivered layout is kept | [34](design/34-staging.md) |

## Reporting

| Item | Today | Where |
|---|---|---|
| OSCAL assessment plan, assessment subjects and risks | assessment results only | [25](design/25-reports-and-controls.md) |
| OSCAL validated with its exact Unicode patterns | checked with an approximation (Python's `re` lacks `\p{L}`) | [25](design/25-reports-and-controls.md) |
| VEX statements in CycloneDX output | components only | [25](design/25-reports-and-controls.md) |
| Unidentified files listed in the CycloneDX output | they are in the manifest and the report's inventory | [25](design/25-reports-and-controls.md) |
| A rule for CM-4 (impact analyses) | evidence present, no rule | [25](design/25-reports-and-controls.md) |
| Long reports grouped by rule, with counts | every finding listed; HTML folds long lists | [25](design/25-reports-and-controls.md) |

## New phases

| Phase | Purpose |
|---|---|
| 2: controls as code | Control-mapped gap reports for coding-agent setups on workstations and repositories, with the same policy and evidence model |
| 3: MCP policy gateway | Runtime enforcement between agents and their tool servers: a rule written once is enforced at the gate, on the workstation and at run time |

## Upkeep

* Keep the "known limits" of the design documents in step with what is built. Doc 19 still lists OpenSSF model signatures, target compatibility and custom-code scanning as not yet done, and doc 20 lists other ecosystems as generic only and vulnerability, secret and egress checks as not done; docs 21, 23, 24 and 29 built them since.
* Release 0.2.0: the changelog's Unreleased section holds the request commands, Zarf completeness, the SkillSpector plugin and the noise fixes from the second trial.
* Re-run [the first real delivery](../examples/demo/real-delivery.md) with the current code; its numbers predate many fixes.
* Add the scanners, SkillSpector included, to the pinned [ai-trial](../examples/ai-trial/README.md) run, as a standing benchmark.
* Pin the GitHub Actions in CI by commit hash rather than by tag.

## Decided against, and why

These are known and recorded, and stay out because a guardrail rules them out ([CONTRIBUTING.md](../CONTRIBUTING.md#guardrails)). Each is reconsidered only if the guardrail can be kept.

| Item | Why not |
|---|---|
| Running what Zarf would run (actions, deployments) to see what it does | never execute what is inspected; deploy actions are reported, not run |
| Checking a Zarf package or manifests against a live cluster | no network at run time; the high side's own tools can do it after staging |
| Publishing staged content to registries, Pulp, Artifactory or WSUS | staging writes local files only; the site's tools publish them ([34](design/34-staging.md)) |
| OPA/Gatekeeper or Kyverno policy evaluation | done better by those tools on the high side ([30](design/30-infrastructure-code.md)) |
| Hugging Face hub datasets whose data files are remote URLs counted as complete | offline, they are missing, and are reported so |
