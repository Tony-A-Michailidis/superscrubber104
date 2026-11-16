# airlock

> **Status: pre-alpha.** `keygen`, `pack`, `verify` and `stage` work end to end, with multi-volume and delta bundles. airlock inspects:
>
> * models, with their publishers' signatures;
> * datasets, knowledge bases and corpora, and notebooks;
> * agent and MCP configuration;
> * container images and VM images;
> * the inference and GPU stack;
> * Python, npm, Java, Go, Rust and .NET environments;
> * OS packages and package mirrors, with vendor signatures;
> * infrastructure code and IDE extensions.
>
> It finds secrets, active content and anything that needs the internet. `airlock patch` plans and stages OS patches from offline security feeds. ClamAV, Trivy, Semgrep, Bandit, qemu-img and osslsigncode run as optional pinned plugins, and models can be evaluated on both sides. Reports (Markdown, HTML, JSON, CycloneDX, OSCAL) are rendered from the evidence. Not ready for real transfers. `airlock` is a working name.

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

## Demo

```console
$ python examples/demo/demo.py
```

The [demo](examples/demo/demo.py) builds a small but complete AI delivery: a sharded chat model with its tokenizer, chat template, card and licence; the application that loads it; a hash-pinned Python wheel; an MCP server and its client configuration; a folder of policy documents declared as a knowledge-base corpus; and an evaluation set. It packs the delivery on the "low side", then verifies it on the "high side" with a policy that pins the packing key. The import is accepted.

Then it tampers with the bundle, as someone with access to the transfer media could:

- changes 16 bytes of weights in one model shard (the file still parses);
- slips in a file that nobody declared;
- adds `training_args.bin`, a pickle whose payload would run a shell command if anything unpickled it.

And verifies again:

```console
$ airlock verify bundle --policy high/policy.yaml --state high/state --out import-2
REFUSE   integrity.entry.unexpected  [28acb79bd69f8e44]
         app/patch-notes.txt: Payload contains content that is not in the manifest
REFUSE   integrity.entry.unexpected  [24ac6f7ab16e6160]
         models/tiny-chat/training_args.bin: Payload contains content that is not in the manifest
REFUSE   integrity.hash.mismatch  [1f3451731f1bf6d0]
         models/tiny-chat/model-00002-of-00002.safetensors: Content does not match the manifest
REFUSE   replay.bundle.already-accepted  [c501d5f35b1d7013]
         bundle: This exact bundle was already accepted
BLOCK    model.pickle.dangerous-import  [d5085f50ae1334e7]
         models/tiny-chat/training_args.bin: Pickle imports a dangerous callable
         approvals: 0 of 2
APPROVE  model.format.code-capable  [04c6860cbcbadba6]
         models/tiny-chat/training_args.bin: Model or data file can run code when loaded
         approvals: 0 of 1
WARN     kb.embedding-model.unrecorded  [e63d460f69e659dc]
         knowledge-base:rag/docs: Knowledge base does not record which embedding model built it
WARN     malware.detected (not assessed)  [f6490e189d646738]
         bundle: Malware scanner reports a detection
         reason: no malware scanner is configured (plugins.clamav)
...
81 of 205 rules exercised, 315 checks passed; findings: 5 block, 1 need approval, 4 warn, 2 allowed
verdict: REFUSED - an integrity or authenticity check failed; this cannot be overridden
```

All three are caught, and the ledger also notices the same bundle arriving a second time, altered. The hash mismatch and the unexpected files are refusals that no policy or approval can override. The pickle is found by reading its opcodes, never by loading it. The scanners the demo does not configure are reported as not assessed, not left out.

Each import also gets its evidence: an HTML report, a CycloneDX SBOM/ML-BOM (the model as a `machine-learning-model` component, the wheel with its purl, hash and licence) and OSCAL assessment results. Every report carries a control matrix:

| Control | Title | Status | Passed | Failed | Not assessed |
|---|---|---|---|---|---|
| CM-8 | System Component Inventory | findings | 98 | 5 | 0 |
| RA-5 | Vulnerability Monitoring and Scanning | not-assessed | 0 | 0 | 2 |
| SC-7 | Boundary Protection | no-findings | 28 | 0 | 0 |
| SI-3 | Malicious Code Protection | findings | 31 | 2 | 1 |
| SI-7 | Software, Firmware, and Information Integrity | findings | 125 | 4 | 0 |

The demo exits 0 only when everything happens as described, and the test suite runs it.

## Usage

What works today:

```console
$ airlock keygen -o keys --name pack --holder build-pipeline
$ airlock pack ./delivery --request request.yaml --key keys/pack.key -o bundle/
$ airlock verify bundle/ --policy policy.yaml --state /var/lib/airlock --key keys/receipt.key --out review/
$ airlock report review/ --format html -o review/report.html
```

- `keygen` prints the snippet that pins the new key in the receiving side's policy.
- `pack` inventories, hashes, inspects and signs.
- `rules` lists every check airlock can record: what it means, its severity, the controls it is evidence for and whether anyone can override it. The same list is in [docs/rules.md](docs/rules.md).
- `report` renders the evidence for reviewers and assessors: Markdown or a self-contained HTML page, JSON, a CycloneDX 1.6 SBOM/ML-BOM, or OSCAL assessment results, with a control matrix that shows, for each NIST SP 800-53 control, what airlock checked, what it found and what it could not assess. See [reports and control mapping](docs/design/25-reports-and-controls.md).
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
$ airlock model inspect models/tiny-chat      # the demo's model
model package  .  (example-org/tiny-chat)
  architecture   LlamaForCausalLM, 648 parameters
  weights        safetensors, 2 file(s), F16 x5
  tokenizer      BPE, 32 tokens
  chat template  sha256:5875dc31f4b023c5... (tokenizer_config.json#chat_template)
  licence        Apache-2.0
  provenance     none recorded, 0 file(s) verified
  members        8
```

`airlock model inspect` records and checks model packages in place: safetensors, GGUF, PyTorch and other pickle-based formats (statically; nothing is ever unpickled), Keras, ONNX, Ollama stores, adapters and sentence-transformers. It checks shards against indexes, configs against tensors, tokenizers against vocabularies, chat templates, `trust_remote_code`, licences and publisher checksums. See [model packages](docs/design/19-model-packages.md).

The same inspection covers the rest of a delivery. MCP configs, agent settings, skills and instruction files are checked for shell launchers, runtime fetches, broad permissions, literal credentials and injected instructions; MCP server code for what its tools can reach. Container images (docker save, OCI archives and layouts) are verified blob by blob, and their layers are inspected like any other archive. Python and npm lockfiles are resolved against the wheels, sdists and tarballs in the delivery, so a requirement that would need the internet on the high side, or a package that does not match its lockfile hash, is caught before transfer. See [agents, containers, packages and source](docs/design/20-software-and-agents.md).

The data around a model is covered too: datasets (Parquet footers, Hugging Face cards and `save_to_disk` layouts, loading scripts), knowledge bases (FAISS, LangChain, Chroma, LlamaIndex, and document folders the transfer request declares as a corpus) with a scan of their documents for planted instructions and hidden text and a check that the embedding model that built each index is in the delivery, notebooks, and classic ML and MLflow models. See [data and knowledge](docs/design/22-data-and-knowledge.md).

Every text file, including files inside container layers and packages, is searched for credentials, and documents for macros, PDF JavaScript and remote templates. Malware scanning, vulnerability scanning and static analysis use ClamAV, Trivy (with the CISA KEV catalogue), Semgrep and Bandit as optional plugins that airlock pins and checks before it trusts them; without them those checks are recorded as not assessed. `airlock plugins check` reports their state. See [scanners](docs/scanners.md).

`airlock offline-check` reports what a delivery will try to download, report or call once disconnected (model hubs, installs, telemetry, cloud AI services, external images) and prints the configuration to set on the high side. A `RuntimeProfile` declares the stack models were tested on; airlock checks it against what is delivered and against NVIDIA's driver/CUDA table and the site's own compatibility rules. See [offline readiness and runtime profiles](docs/design/23-offline-and-runtime.md).

Publishers' OpenSSF model signatures are verified offline (a pinned key, a CA, or Sigstore keyless against a pinned trusted root), and `airlock eval run` runs a pinned evaluation set through a pinned local runtime on each side and compares the answers, so a swapped or misbehaving model is caught. See [signatures and evaluation](docs/design/24-signatures-and-eval.md).

OS packages and mirrors are checked as their vendors sign them, with keys pinned in the policy and limited by scope:
* RPM header and payload digests and signatures, and Debian packages;
* dnf and apt mirrors, as a chain from signed `repomd.xml` or `InRelease` to every package;
* PyPI simple, npm and Helm repositories;
* publishers' `SHA256SUMS` and detached signatures.

Stale, expired or rolled-back repository metadata is caught against the receiving side's ledger. See [vendor trust](docs/design/27-vendor-trust.md) and [package mirrors](docs/design/28-package-mirrors.md).

Gradle, Go, Cargo and NuGet lockfiles are resolved against the delivery with their hashes (Go's `h1:`, crate checksums, NuGet content hashes), and build-time hooks are recorded ([more ecosystems](docs/design/29-more-ecosystems.md)). For infrastructure code ([infrastructure code](docs/design/30-infrastructure-code.md)):
* Kubernetes and Compose workloads are checked for privileged and host access and for images by tag rather than digest;
* Helm, Terraform and Ansible dependencies must be vendored;
* Terraform providers are checked against `.terraform.lock.hcl`.

VS Code and JetBrains extensions are identified for approved lists, with telemetry and start-up activation recorded ([IDE extensions](docs/design/31-ide-extensions.md)). VM disk images are read from their headers and never mounted ([VM images](docs/design/32-vm-images.md)):
* qcow2, VMDK, VHD, VHDX, raw and ISO;
* incomplete, encrypted, unclean and format-confused images are caught;
* OVA manifests and Glance hashes and signatures are checked.

Large deliveries can be cut into volumes, one per medium, under one signed index (`pack --volume-size`). Recurring transfers can be deltas against a bundle the receiving side already accepted (`pack --delta-from`). See [volumes and deltas](docs/design/26-volumes-and-deltas.md).

```console
$ airlock patch inventory --root / --label web-01 --key keys/receipt.key -o web-01.json     # high side
$ airlock patch plan --inventory web-01.json --feed updateinfo.xml.gz --feed kev.json \
      --policy policy.yaml -o plan.json --markdown plan.md                                  # low side
$ airlock patch stage bundle/ --inventory web-01.json --policy policy.yaml \
      --state /var/lib/airlock --key keys/receipt.key --target dnf=/srv/repos               # high side
```

`airlock patch` keeps disconnected AlmaLinux, Ubuntu and Windows hosts patched:
* The high side's inventory crosses outbound, signed, and holds package names and versions only.
* It is matched against offline OSV, dnf `updateinfo`, Microsoft CVRF and CISA KEV snapshots. Stale feeds are refused.
* Emergency plans narrow the result to `--kev` or `--cve`.
* `patch stage` refuses downgrades unless they are justified.
* `patch confirm` shows the gap closed.
* Hosts whose package database cannot be read directly (AlmaLinux 8) give a package listing instead.

See [patching and feeds](docs/design/33-patching-and-feeds.md). `airlock stage` places an accepted bundle into local stores (a PEP 503 index, Verdaccio storage, dnf and apt mirrors, OCI layouts, model directories, a Windows share). It re-hashes every file as it copies it, keeps a stage report, and records the event in the ledger, including a staging that failed part-way. It never pushes over the network. See [staging](docs/design/34-staging.md).

`airlock approve` signs approvals and overrides; `airlock ledger adjust-clock` is the logged recovery path when a disconnected host's clock has drifted.

## Roadmap

| Phase | Module | Purpose | Status |
|---|---|---|---|
| 1 | `pack` / `verify` / `report` | Inventory, hash, scan, sign, bundle and verify any delivery, AI and non-AI, with control-mapped evidence | built |
| 1b | offline readiness and coverage | Prove the delivery runs disconnected; runtime profiles, mirrors, VM images, IaC, IDE extensions, Java/Go/Rust/.NET, multi-volume bundles | built |
| 1c | `patch` / `stage` | Keep disconnected Windows, AlmaLinux and Ubuntu systems patched, with a fast lane for actively exploited CVEs; delta bundles; staging | built (GPU driver and firmware advisories to come) |
| 1d | `eval` | Behavioural verification of models on both sides of the gap; model signatures | built |
| 2 | controls-as-code | Control-mapped gap reports for coding-agent setups | planned |
| 3 | MCP policy gateway | Runtime enforcement between agents and MCP servers | planned |

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
