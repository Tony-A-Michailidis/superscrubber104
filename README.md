# airlock

> **Status: pre-alpha.** `keygen`, `pack` and `verify` work end to end (integrity, signing, archive inspection, replay protection). Models (with their publishers' signatures), datasets, knowledge bases and corpora, notebooks, agent and MCP configuration, container images, the inference and GPU stack, and Python and npm environments are inspected; secrets, active content and anything that needs the internet are found; ClamAV, Trivy, Semgrep and Bandit run as optional pinned plugins; models can be evaluated on both sides. Reports are next. Not ready for real transfers. `airlock` is a working name.

**Make agentic AI projects accreditable in high-assurance and disconnected environments.**

AI projects are usually built on connected, unclassified networks and then have to move, in full, to classified networks that have no internet connection. A delivery like that holds much more than model weights. It also includes inference runtimes, GPU drivers, Python wheels, container images, vector indexes, MCP servers, IDE extensions, infrastructure code, VM images and OS patches. Each one could be tampered with, malicious, incomplete or quietly dependent on the internet.

`airlock` prepares such a delivery for transfer across an air gap and verifies it on the other side:

- **Inventory everything.** Every file is hashed and recorded, and anything unrecognised is still signed and listed as "unclassified", never dropped.
- **Understand units, not just files.** Model packages, runtime profiles, Python environments and knowledge bases are checked for completeness and internal consistency.
- **Inspect without executing.** Pickle payloads, `trust_remote_code`, Keras Lambda layers, install scripts and agent hooks are found by static analysis only.
- **Prove offline readiness.** Telemetry, auto-downloads, auto-updaters and hard-coded cloud endpoints are flagged.
- **Two layers of trust.** Our signature proves the bundle was not altered in transit. Upstream signatures and checksums prove the content is genuine.
- **Evidence-first.** Every check emits a finding mapped to NIST SP 800-53 Rev 5 / ITSG-33 controls, ready to attach to a security assessment and authorization (SA&A) package.

It runs fully offline, has minimal dependencies, and is designed to cross its own airlock.

## Usage

What works today:

```console
$ airlock keygen -o keys --name pack --holder build-pipeline
$ airlock pack ./delivery --request request.yaml --key keys/pack.key -o bundle/
$ airlock verify bundle/ --policy policy.yaml --state /var/lib/airlock --key keys/receipt.key
```

- `keygen` prints the snippet that pins the new key in the receiving side's policy.
- `pack` inventories, hashes, inspects and signs.
- `verify` trusts nothing the packer said. It checks the signature against keys pinned in its own policy, re-hashes every byte, re-inspects the content with its own limits, and records the import in a hash-chained ledger so that replayed, stale or out-of-order bundles are caught.

Exit codes make the commands usable as CI gates:

| Code | Meaning |
|---|---|
| 0 | Accepted |
| 1 | A policy blocker stands, or approvals are outstanding |
| 2 | Usage or configuration error |
| 3 | Refused: an integrity or authenticity check failed |

Two kinds of failure are kept strictly apart:

- **Integrity and authenticity failures** (hash mismatch, bad or missing signature, replay, wrong enclave) can never be waived or overridden, by policy or by anyone. If they could, the airlock would not be a control.
- **Policy blockers** (a pickle model, remote code, a licence, an unapproved package) can be overridden for one bundle with `airlock approve`, but only by a quorum of approvers with a written justification. The packer cannot approve its own bundle, and the override is recorded as signed evidence.

See [examples/policy.yaml](examples/policy.yaml) and [examples/request.yaml](examples/request.yaml), and the [bundle format and verification steps](docs/design/18-bundle-and-verification.md), including its list of known limits.

```console
$ airlock model inspect ./models/tiny-chat
model package  .  (example-org/tiny-chat)
  architecture   LlamaForCausalLM, 1.2B parameters
  weights        safetensors, 4 file(s), BF16 x291
  tokenizer      BPE, 128256 tokens
  chat template  sha256:5f1b6c0e4a1d2b3c... (tokenizer_config.json#chat_template)
  licence        LicenseRef-llama3.1 (gated)
  provenance     huggingface-download-record example-org/tiny-chat@0123abc..., 6 file(s) verified
```

`airlock model inspect` records and checks model packages in place: safetensors, GGUF, PyTorch and other pickle-based formats (statically; nothing is ever unpickled), Keras, ONNX, Ollama stores, adapters and sentence-transformers. It checks shards against indexes, configs against tensors, tokenizers against vocabularies, chat templates, `trust_remote_code`, licences and publisher checksums. See [model packages](docs/design/19-model-packages.md).

The same inspection covers the rest of a delivery. MCP configs, agent settings, skills and instruction files are checked for shell launchers, runtime fetches, broad permissions, literal credentials and injected instructions; MCP server code for what its tools can reach. Container images (docker save, OCI archives and layouts) are verified blob by blob, and their layers are inspected like any other archive. Python and npm lockfiles are resolved against the wheels, sdists and tarballs in the delivery, so a requirement that would need the internet on the high side, or a package that does not match its lockfile hash, is caught before transfer. See [agents, containers, packages and source](docs/design/20-software-and-agents.md).

The data around a model is covered too: datasets (Parquet footers, Hugging Face cards and `save_to_disk` layouts, loading scripts), knowledge bases (FAISS, LangChain, Chroma, LlamaIndex, and document folders the transfer request declares as a corpus) with a scan of their documents for planted instructions and hidden text and a check that the embedding model that built each index is in the delivery, notebooks, and classic ML and MLflow models. See [data and knowledge](docs/design/22-data-and-knowledge.md).

Every text file, including files inside container layers and packages, is searched for credentials, and documents for macros, PDF JavaScript and remote templates. Malware scanning, vulnerability scanning and static analysis use ClamAV, Trivy (with the CISA KEV catalogue), Semgrep and Bandit as optional plugins that airlock pins and checks before it trusts them; without them those checks are recorded as not assessed. `airlock plugins check` reports their state. See [scanners](docs/scanners.md).

`airlock offline-check` reports what a delivery will try to download, report or call once disconnected (model hubs, installs, telemetry, cloud AI services, external images) and prints the configuration to set on the high side. A `RuntimeProfile` declares the stack models were tested on; airlock checks it against what is delivered and against NVIDIA's driver/CUDA table and the site's own compatibility rules. See [offline readiness and runtime profiles](docs/design/23-offline-and-runtime.md).

Publishers' OpenSSF model signatures are verified offline (a pinned key, a CA, or Sigstore keyless against a pinned trusted root), and `airlock eval run` runs a pinned evaluation set through a pinned local runtime on each side and compares the answers, so a swapped or misbehaving model is caught. See [signatures and evaluation](docs/design/24-signatures-and-eval.md).

`airlock approve` signs approvals and overrides; `airlock ledger adjust-clock` is the logged recovery path when a disconnected host's clock has drifted.

Planned: `airlock report`, `airlock stage`, `airlock patch`.

## Roadmap

| Phase | Module | Purpose |
|---|---|---|
| 1 | `pack` / `verify` | Inventory, hash, scan, sign, bundle and verify any delivery, AI and non-AI |
| 1b | offline readiness | Prove the delivery runs disconnected with no egress paths |
| 1c | `patch` | Keep disconnected Windows, AlmaLinux and Ubuntu systems patched, with a fast lane for actively exploited CVEs |
| 1d | `eval` | Behavioural verification of models on both sides of the gap |
| 2 | controls-as-code | Control-mapped gap reports for coding-agent setups |
| 3 | MCP policy gateway | Runtime enforcement between agents and MCP servers |

The design documents are in [docs/design/](docs/design/README.md).

## Development

Requires Python 3.11+.

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ pre-commit install
$ pytest
```

The test suite blocks all network access. If a test needs a socket, that is a design bug.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
