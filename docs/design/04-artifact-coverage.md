# 6. Artifact coverage

Each category is a handler with the same interface: `detect()`, `inventory()` (identity, version, purl/model id, licence, metadata), `components()`, `units()` (contributions to unit grouping), `checks()`.

## AI-specific

| Category | Examples | Type-specific handling |
|---|---|---|
| **Model weights (safe formats)** | `.safetensors` (incl. sharded with `model.safetensors.index.json`), `.gguf` (incl. split GGUF), GPTQ/AWQ/EXL2/MLX quantized safetensors | Header parsing (no framework import), tensor count/size sanity, shard completeness vs index, GGUF metadata extraction (architecture, quantization, embedded chat template, tokenizer) |
| **Model weights (code-capable formats)** | PyTorch `.pt`/`.pth`/`.bin`/`.ckpt`, `.pkl`, `.joblib`, `.npy`/`.npz` with object arrays, Keras `.h5`/`.keras`, TensorFlow SavedModel, ONNX (custom ops, external data files) | Pickle opcode analysis for dangerous imports, Keras Lambda/custom layer detection, TF custom op detection, ONNX external-data completeness. **Policy default: block or require approval; recommend conversion to safetensors** |
| **Opaque or hardware-bound models** | TensorRT `.engine`/`.plan`, OpenVINO IR, CoreML, TFLite, compiled/AOT artifacts | Treated as binaries with model metadata; record target hardware/runtime version; flag that content cannot be inspected |
| **Executable model bundles** | llamafile and similar weight+executable polyglots | Treated as executables (malware scan, signature) **and** models |
| **Model package files** | `config.json`, `generation_config.json`, `tokenizer.json`/`tokenizer.model`/`vocab.*`/`merges.txt`, `special_tokens_map.json`, chat templates (Jinja), Ollama Modelfiles and manifests, model cards, `LICENSE`/use policy | Grouped into a `ModelPackage` ([§7](05-model-packages.md)); template inspection; config ↔ weights consistency |
| **Custom model code** | `modeling_*.py`, `configuration_*.py`, `auto_map` entries requiring `trust_remote_code` | **Blocker by default**; if approved, treated as source code (SAST, secrets, egress scan) and pinned by hash |
| **Adapters and fine-tunes** | LoRA/QLoRA/PEFT (`adapter_config.json`, `adapter_model.safetensors`), merged checkpoints | Base-model linkage recorded and verified against a base model in the bundle or already on the high side |
| **Multimodal and task models** | Vision projectors (`mmproj`), CLIP/vision encoders, Whisper/ASR, TTS voices, detection/segmentation (e.g. YOLO `.pt`), OCR models | Same format rules as above; grouped into the parent `ModelPackage` where applicable |
| **Classic ML** | scikit-learn, XGBoost/LightGBM/CatBoost model files | Format detection; pickle-based ones follow code-capable rules |
| **Embedding models and rerankers** | Sentence-transformer packages, reranker models | `ModelPackage` plus recorded embedding dimension, normalisation and pooling, needed for knowledge-base consistency |
| **Guardrail and safety models** | Content classifiers, prompt-injection detectors, PII detectors | `ModelPackage`; flagged as security-relevant components in the report |
| **Inference runtimes** | Ollama, llama.cpp, vLLM, TGI, Triton, ONNX Runtime, OpenVINO runtime (binaries, packages or container images) | Recorded in a `RuntimeProfile` ([§8](06-runtime-profiles.md)); version and signature checks; telemetry/update settings ([§10](08-offline-readiness.md)) |
| **GPU and accelerator stack** | NVIDIA drivers (`.run`, RPM/DEB), CUDA toolkit, cuDNN, NCCL, TensorRT, NVIDIA container toolkit, ROCm | Vendor signature/checksum verification, versions recorded in the `RuntimeProfile`, compatibility checks |
| **ML Python stack** | PyTorch/TensorFlow/JAX wheels (CUDA variants), transformers, sentence-transformers, LangChain/LlamaIndex etc. | Language-package handling plus CUDA-variant tagging and wheel-platform compatibility with the target |
| **RAG and knowledge assets** | Vector DB snapshots (Chroma, Qdrant, Milvus, pgvector dumps, FAISS indexes), knowledge-graph exports (Neo4j dumps, Cypher scripts), document corpora, chunking/ingestion configs | Grouped into a `KnowledgeBase` ([§9](07-knowledge-bases-and-agents.md)): embedding-model consistency, corpus inventory, prompt-injection scan of corpus content, format safety (FAISS/pickle metadata) |
| **Agent and MCP assets** | MCP servers (source, packages, container images), MCP client configs, agent skills (`SKILL.md` + scripts), agent hooks, slash commands, agent permission settings, system prompts, tool definitions | MCP tool lint, hook/skill script analysis (hooks execute shell), permission breadth, prompt-injection markers; feeds phase 2 |
| **Datasets** | `.parquet`, `.jsonl`, `.csv`, Arrow, HF `datasets` folders, training/eval sets | Inventory (rows, schema, hash), licence, optional PII and secrets scan, ML-BOM dataset component |
| **Evaluation assets** | Eval prompt sets, expected outputs, benchmark configs, previous results | Inputs to `superscrubber104 eval` ([§11](09-behavioural-verification.md)); pinned by hash |
| **Notebooks** | `.ipynb` | Treated as source; **saved outputs flagged** (may carry data, tokens or paths); option to require stripped outputs |

## Developer environment and package ecosystems

| Category | Examples | Type-specific handling |
|---|---|---|
| **IDE extensions** | VS Code `.vsix` (incl. AI assistants such as Continue/Cline configured for local models), JetBrains plugins | Marketplace signature verification where present, publisher and extension ID, declared activation events and capabilities, bundled binaries, telemetry and update settings, extension dependencies included |
| **Python environments** | `requirements.txt` with hashes, `uv.lock`/`poetry.lock`/`Pipfile.lock`, wheelhouses, conda environments and channels, `conda-pack` archives | **Offline resolvability:** verify the wheelhouse satisfies the lockfile with no network (index-free resolution); hash pinning; platform/ABI tags match the target |
| **Other language environments** | npm offline cache / vendored `node_modules`, Maven/Gradle offline repos, Go module cache / `vendor/`, `cargo vendor`, NuGet offline feeds | Same offline-resolvability principle per ecosystem |
| **Package mirror subsets** | Curated PyPI/npm/Maven/conda/Hugging Face mirror snapshots for Nexus, Artifactory, devpi, Verdaccio, Harbor | `RepoMirror` unit: index metadata vs content consistency, delta against last accepted snapshot |
| **Offline documentation** | Docsets (Zeal/Dash), devdocs exports, static doc sites, framework docs | Inventory, active content check (scripts in HTML), external link/asset references flagged |
| **Developer tool binaries** | CLIs, language toolchains, SDKs, git, editors | Executable handling (signature, malware scan, version) |

## General software and infrastructure

| Category | Examples | Type-specific handling |
|---|---|---|
| **Container images** | `docker save` / `podman save` tarballs, OCI layouts, image lists to export from a local daemon | Per-layer inventory, OS + language package SBOM, root user / missing USER, secrets in layers, base image identity, digest pinning, signature/attestation if present, embedded models detected and handled as models |
| **Source code** | Repo folders, `git bundle`, archives in any language (Python, JS/TS, Java/Kotlin, Go, Rust, C/C++, C#, Ruby, PHP, shell, PowerShell) | Language detection, lockfile/manifest parsing, optional SAST, secrets scan **including git history** in bundles, licence headers, generated/minified code flagged, commit signature status recorded |
| **Language packages** | Wheels/sdists, npm tarballs, JARs/WARs, Go modules, Cargo crates, NuGet, gems, Composer | purl identity, nested dependencies, install-script detection (npm `postinstall`, `setup.py`, build hooks), approved-package allowlist |
| **Linux OS packages and repos** | **AlmaLinux** (RPM, dnf repo mirrors with `repodata/`, modular metadata, `updateinfo.xml`) and **Ubuntu** (DEB, apt mirrors with `Release`/`InRelease`/`Packages`, `-security` pocket), plus APK | Vendor GPG verification on packages *and* repo metadata, ALSA/USN mapping, dependency closure, freshness and downgrade checks ([§13](11-os-patching.md)) |
| **Windows updates and installers** | MSU, CAB, MSI/MSP, EXE installers, WSUS exports, drivers, Defender/AV definitions | Authenticode and chain verification, KB↔CVE mapping, supersedence, `.cat` checks ([§13](11-os-patching.md)) |
| **Firmware and appliance images** | BIOS/UEFI capsules, LVFS/fwupd `.cab`, firewall/switch/storage firmware, hypervisor/appliance upgrades, GPU firmware | Vendor signature/hash verification, version inventory, advisory mapping where available |
| **Security content feeds** | Vulnerability DBs (OSV, Grype/Trivy DB), CISA KEV, vendor OVAL, AV signatures, SAST rule packs, CA trust stores, CRLs | Source verification, **age recorded as evidence**, policy maximum age |
| **Infrastructure and deployment** | Helm charts, Kubernetes manifests (incl. K3s), Docker Compose, Terraform modules/providers, Ansible roles/collections, CI pipeline files | Referenced images/modules/providers added to inventory and **required to be present** (offline completeness), misconfiguration checks (privileged pods, hostPath, `latest` tags, embedded secrets, external registries) |
| **VM and disk images** | **qcow2 from OpenStack exports** (Glance downloads, instance/volume snapshots, with or without Glance metadata JSON), raw (incl. Ceph `rbd export`), OVA/OVF, VMDK, ISO | [§12](10-vm-images.md) |
| **Binaries and executables** | ELF, PE, Mach-O, static Go/Rust binaries | Type identification, version strings, malware scan, signature checks |
| **Documents and media** | PDF, Office, Markdown, images | Macro/active content, metadata leakage (authors, paths, hostnames), secrets in text, prompt-injection markers when destined for a RAG corpus |
| **Archives** | zip, tar(.gz/.xz/.zst), 7z | Safe recursive extraction: depth and size limits, zip-bomb and path-traversal protection, symlink/hardlink handling |
| **Unknown** | Anything else | Hash, sign, generic secrets and malware scan, recorded as "unclassified" |
