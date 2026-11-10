# Roadmap

## 15. Phases

- **1a (core):**
  - core models, the walker with safe archive extraction, and the generic handler
  - keygen/pack/verify, transfer request, reports
  - **model packages** (safe and code-capable formats, shards, tokenizer, chat template, `trust_remote_code`, licence, provenance)
  - MCP and agent assets
  - container image tarballs
  - Python and JS/TS source, packages and environments, with offline resolvability
- **1b:**
  - runtime profiles, knowledge bases (RAG), datasets, notebooks
  - IDE extensions and package mirror subsets
  - **offline readiness**
  - OpenStack qcow2/raw images
  - Java, Go, Rust and C#
  - Helm/Kubernetes/Terraform/Ansible, documents, multi-volume bundles
- **1c:**
  - `airlock patch` for AlmaLinux and Ubuntu, then Windows
  - GPU driver/CUDA and firmware updates
  - security feeds with freshness checks
  - delta bundles
- **1d:** `airlock eval`, OpenSSF model-signature verification, sandboxed model conversion.
- **2:** controls-as-code for coding agents.
- **3:** MCP policy gateway.
- **Later:** libguestfs deep inspection, OVA/VMDK/ISO internals, firmware advisory mapping, deeper binary analysis, datasets at scale, outbound (high-to-low) release checks.


## 20. First tasks for Claude Code

1. Split this brief into `docs/design/*.md`; trim `CLAUDE.md` to an index.
2. Scaffold: `pyproject.toml`, Apache-2.0 licence, README skeleton, CI (GitLab CI and/or GitHub Actions), pre-commit, pytest.
3. Core models: `TransferRequest`, `Bundle`, `Artifact`, `Component`, `Unit`, `Manifest`, `Finding`, `Policy`, `ControlMapping`, `Receipt`; `Handler`, `Plugin`, `Stager` interfaces.
4. Walker with safe extraction + generic handler + keygen/pack/verify (hashing and signing only), end to end, with tamper, zip-bomb and path-traversal tests.
5. Model packages: safetensors/GGUF parsing, pickle opcode scanner (static, never unpickle), shard/tokenizer/template/config checks, `trust_remote_code` detection, licence and provenance capture.
6. Remaining 1a handlers (MCP/agents, containers, Python/JS source/packages/environments), each with fixtures.
7. Cross-cutting checks, then optional scanner plugins.
8. Report rendering and control mapping.
9. README demo: pack a mixed AI project delivery, tamper with one shard, add an undeclared file and a pickle payload, and show `verify` catching all three, with the report listing every component and control.
