# superscrubber104

[![CI](https://github.com/Tony-A-Michailidis/superscrubber104/actions/workflows/ci.yml/badge.svg)](https://github.com/Tony-A-Michailidis/superscrubber104/actions/workflows/ci.yml)

> **Pre-alpha.** It works end to end, but it is not yet ready for real transfers.

**Make agentic AI projects accreditable in high-assurance and disconnected environments.**

superscrubber104 prepares a complete AI delivery for transfer across an air gap and verifies it on the other side. It inspects everything that crosses, without running any of it, and records control-mapped evidence for the security assessment.

## Why

AI projects are usually built on connected, unclassified networks and then have to move, in full, to classified networks that have no internet connection. A delivery like that holds much more than model weights. It also includes inference runtimes, GPU drivers, Python wheels, container images, vector indexes, MCP servers, IDE extensions, infrastructure code, VM images and OS patches. Each one could be tampered with, malicious, incomplete or quietly dependent on the internet.

- **Inventory everything.** Every file is hashed and recorded, and anything unrecognised is still signed and listed as "unclassified", never dropped.
- **Understand units, not just files.** Model packages, runtime profiles, Python environments and knowledge bases are checked for completeness and internal consistency.
- **Inspect without executing.** Pickle payloads, `trust_remote_code`, Keras Lambda layers, install scripts and agent hooks are found by static analysis only.
- **Prove offline readiness.** Telemetry, auto-downloads, auto-updaters and hard-coded cloud endpoints are flagged.
- **Two layers of trust.** Our signature proves the bundle was not altered in transit. Upstream signatures and checksums prove the content is genuine.
- **Evidence-first.** Every check emits a finding mapped to NIST SP 800-53 Rev 5 controls, ready to attach to a security assessment and authorization (SA&A) package. A site can load its own control profile, such as ITSG-33, instead.

Integrity and authenticity failures (a hash mismatch, a bad signature, a replay, the wrong enclave) can never be waived or overridden. Policy blockers (a pickle model, remote code, a licence) can be overridden for one bundle, but only by a quorum of approvers with a written justification, recorded as signed evidence.

It runs fully offline, has minimal dependencies, and is designed to cross its own airlock.

## Demo

To install superscrubber104 and run the demo yourself, follow the [quick start](docs/quickstart-wsl.md) (WSL on AlmaLinux 9 or 10; the steps work on any Linux with Python 3.11+).

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
$ superscrubber104 verify bundle --policy high/policy.yaml --state high/state --out import-2
REFUSE          integrity.entry.unexpected  [28acb79bd69f8e44]
                app/patch-notes.txt: Payload contains content that is not in the manifest
REFUSE          integrity.entry.unexpected  [24ac6f7ab16e6160]
                models/tiny-chat/training_args.bin: Payload contains content that is not in the manifest
REFUSE          integrity.hash.mismatch  [1f3451731f1bf6d0]
                models/tiny-chat/model-00002-of-00002.safetensors: Content does not match the manifest
REFUSE          replay.bundle.already-accepted  [c501d5f35b1d7013]
                bundle: A bundle with this id and signed statement was already accepted
BLOCK           model.pickle.dangerous-import  [d5085f50ae1334e7]
                models/tiny-chat/training_args.bin: Pickle imports a dangerous callable
                approvals: 0 of 2 required
NEEDS APPROVAL  model.format.code-capable  [04c6860cbcbadba6]
                models/tiny-chat/training_args.bin: Model or data file can run code when loaded
                approvals: 0 of 1 required
WARN            kb.embedding-model.unrecorded  [e63d460f69e659dc]
                knowledge-base:rag/docs: Knowledge base does not record which embedding model built it
WARN            not assessed: malware.detected  [f6490e189d646738]
                bundle: the check did not run: no malware scanner is configured (plugins.clamav)
...
82 of 212 rules exercised, 316 checks passed; findings: 5 block, 1 need approval, 4 warn, 2 allowed
verdict: REFUSED - an integrity or authenticity check failed; this cannot be overridden
```

All three are caught, and the ledger also notices the same signed bundle arriving a second time. The hash mismatch and the unexpected files are refusals that no policy or approval can override. The pickle is found by reading its opcodes, never by loading it. The scanners the demo does not configure are reported as not assessed, not left out.

Each import also gets its evidence: an HTML report, a CycloneDX SBOM/ML-BOM (the model as a `machine-learning-model` component, the wheel with its purl, hash and licence) and OSCAL assessment results. Every report carries a control matrix:

| Control | Title | Status | Passed | Failed | Not assessed |
|---|---|---|---|---|---|
| CM-8 | System Component Inventory | findings | 98 | 5 | 0 |
| RA-5 | Vulnerability Monitoring and Scanning | not-assessed | 0 | 0 | 2 |
| SC-7 | Boundary Protection | no-findings | 28 | 0 | 0 |
| SI-3 | Malicious Code Protection | findings | 31 | 2 | 1 |
| SI-7 | Software, Firmware, and Information Integrity | findings | 125 | 4 | 0 |

The demo exits 0 only when everything happens as described, and the test suite runs it. Its full output is in [examples/demo/sample-output.md](examples/demo/sample-output.md).

## A real delivery

The demo's files are synthetic. superscrubber104 has also been tried on 3.5 GB of real, public projects: the [private-gpt](https://github.com/zylon-ai/private-gpt) RAG application, the [MCP reference servers](https://github.com/modelcontextprotocol/servers) and a client configuration that starts them, three Hugging Face models with every format their repositories publish, a small client with hash-pinned wheels, and the `python:3.12-slim` image. It inspected 1,800 files and 5,645 archive members in 27 seconds and blocked the delivery for 19 reasons, each one real:

| Blockers | Why |
|---|---|
| 2 × `mcp.server.runtime-fetch` | `uvx` and `npx` download the MCP servers when they start |
| 5 × `*.environment.unresolvable` | private-gpt, three Python MCP servers and the npm workspace arrived without their packages |
| 8 × `offline.endpoint.cloud-ai` | private-gpt defaults to `api.openai.com` |
| 1 × `model.pickle.unknown-import` | a model's `training_args.bin` is a pickle importing training classes, which inference does not need |
| 3 × `mcp.server.capability` (shell) | the MCP repository's release scripts start processes |

The first run also reported findings that were superscrubber104's mistakes: a multi-platform image saved for one platform was called incomplete, coreutils' `sha256sum` was taken for a checksum list, an application's `skills` package for agent skills. Each was fixed with a regression test built from the real layout. [The full account](examples/demo/real-delivery.md) and [the report itself](examples/demo/real-delivery-report.pdf) (PDF) are in `examples/demo/`.

One of the models, `HuggingFaceTB/SmolLM2-135M-Instruct` at revision `12fd25f77366fa6b3b4b768ec3050bf629380bac`, inspected in place:

```console
$ superscrubber104 model inspect smollm2-135m
model package  .  (LlamaForCausalLM)
  architecture   LlamaForCausalLM, 134.5M parameters
  weights        safetensors, 1 file(s), BF16 x272
  tokenizer      BPE, 49152 tokens
  chat template  sha256:872be49dbb638044... (tokenizer_config.json#chat_template)
  licence        Apache-2.0
  provenance     huggingface-download-record unknown@12fd25f77366fa6b3b4b768ec3050bf629380bac, 25 file(s) verified
  members        34
...
BLOCK           model.pickle.unknown-import  [3f930721fb6da0fb]
                training_args.bin!/training_args/data.pkl: Pickle imports callables outside the known-safe set
                hint: add trusted classes to the policy's 'pickle-globals' allowlist
                approvals: 0 of 2 required
...
32 of 212 rules exercised, 252 checks passed; findings: 1 block, 10 need approval, 2 warn, 35 allowed
verdict: BLOCKED - a policy blocker stands; it can be overridden by an approval quorum
```

The 25 files verified are checked against the hashes Hugging Face's own download tool recorded. Of the 10 approvals, 9 are the Apache-2.0 licence of the model and its eight ONNX variants (the default policy asks for approval of every licence; a site policy lists the ones it accepts), and one is `training_args.bin`, a file that can run code when loaded.

## Quick start

Requires Python 3.11+. From a clone: `pip install -e .` (the [WSL guide](docs/quickstart-wsl.md) has every step).

**1. A key for the packing side.** `keygen` prints the policy snippet that pins it:

```console
$ superscrubber104 keygen -o keys --name pack --holder build-pipeline
```

**2. The receiving side's policy**, `policy.yaml`, with that snippet pasted in as `trust:`:

```yaml
apiVersion: superscrubber104/v1alpha1
kind: Policy
metadata:
  name: high-side
  version: "1"
identity:
  enclave: enclave-b
licences:
  allow: [Apache-2.0, MIT, BSD-3-Clause]
trust:                         # as printed by keygen
  signers:
    - keyId: "ed25519:…"
      publicKey: keys/pack.pub
      sha256: "…"
      holder: build-pipeline
      roles: [pack]
```

**3. A transfer request**, `request.yaml`, saying what is meant to cross:

```yaml
apiVersion: superscrubber104/v1alpha1
kind: TransferRequest
metadata:
  id: TR-0001
  title: First delivery
spec:
  purpose: Try superscrubber104 on a small delivery
  owner: {name: Example Owner, contact: owner@example.org}
  source: dev-unclass
  destination: enclave-b
  direction: low-to-high
  contents:
    - name: app
      paths: ["app/**"]
```

**4. Pack on one side, verify on the other, render the evidence:**

```console
$ superscrubber104 pack delivery --request request.yaml --key keys/pack.key -o bundle
$ superscrubber104 verify bundle --policy policy.yaml --state state --out import
WARN            not assessed: malware.detected  [f6490e189d646738]
                bundle: the check did not run: no malware scanner is configured (plugins.clamav)
WARN            not assessed: replay.bundle.expired  [0d542c3bfff6f26f]
                bundle: the check did not run: the policy does not set transfer.maxBundleAge
...
32 of 212 rules exercised, 36 checks passed; findings: 0 block, 0 need approval, 4 warn, 0 allowed
verdict: PASSED
$ superscrubber104 report import -f html -o import/report.html
```

`--state` keeps the receiving side's ledger, which is how replayed and out-of-order bundles are caught. The full examples, with every policy setting explained, are [examples/policy.yaml](examples/policy.yaml) and [examples/request.yaml](examples/request.yaml). `superscrubber104 model inspect DIR` checks content in place, without packing.

Exit codes are the same for every command, so they work as CI gates:

| Code | Meaning |
|---|---|
| 0 | Accepted |
| 1 | A policy blocker stands, or approvals are outstanding |
| 2 | Usage or configuration error |
| 3 | Refused: an integrity or authenticity check failed, or the tool itself failed part-way |

## What it checks

One line per area; [docs/features.md](docs/features.md) has the detail and each design document the specification. `superscrubber104 rules` lists every check, as does [docs/rules.md](docs/rules.md).

**AI-specific**

| Area | What superscrubber104 checks |
|---|---|
| [Model packages](docs/design/19-model-packages.md) | safetensors, GGUF, pickle formats (read statically, never unpickled), Keras, ONNX, Ollama, adapters; shards, configs, tokenizers, chat templates, `trust_remote_code`, licences, publisher checksums |
| [Model signatures and evaluation](docs/design/24-signatures-and-eval.md) | OpenSSF model signatures verified offline; a pinned evaluation set run on both sides to catch a swapped model |
| [Agents and MCP](docs/design/20-software-and-agents.md) | MCP configs, agent settings, skills, hooks and instruction files: shell launchers, runtime fetches, broad permissions, credentials, injected instructions; what each MCP server's tools can reach |
| [Data and knowledge](docs/design/22-data-and-knowledge.md) | datasets, knowledge bases and declared corpora (planted instructions, hidden text, the embedding model that built each index), notebooks, classic ML models |
| [Offline readiness and runtime](docs/design/23-offline-and-runtime.md) | model hub downloads, installs, telemetry and cloud AI endpoints; the declared runtime stack against what is delivered |

**Software supply chain**

| Area | What superscrubber104 checks |
|---|---|
| [Bundles and verification](docs/design/18-bundle-and-verification.md) | every file hashed and signed; re-hashed and re-inspected on arrival; a hash-chained ledger against replay; [volumes and deltas](docs/design/26-volumes-and-deltas.md) |
| [Containers, Python and npm](docs/design/20-software-and-agents.md) | images verified blob by blob, layers inspected; lockfiles resolved against the packages delivered |
| [Java, Go, Rust, .NET](docs/design/29-more-ecosystems.md) | Gradle, Go, Cargo and NuGet lockfiles resolved with their hashes; build-time hooks |
| [Vendor trust](docs/design/27-vendor-trust.md) | RPM signatures and digests, Debian packages, publishers' checksum lists and detached OpenPGP signatures, against keys pinned in the policy |
| [Package mirrors](docs/design/28-package-mirrors.md) | dnf, apt, PyPI, npm and Helm repositories as signed chains; stale or rolled-back metadata |
| [Secrets, executables, documents, scanners](docs/design/21-scanners-and-basics.md) | credentials in every text file; macros and PDF JavaScript; ClamAV, Trivy with CISA KEV, Semgrep and Bandit as pinned plugins |
| [Infrastructure code](docs/design/30-infrastructure-code.md) | Kubernetes, Compose, Helm, Terraform and Ansible: privileged workloads, unpinned images, unvendored dependencies |
| [IDE extensions](docs/design/31-ide-extensions.md) | VS Code and JetBrains extensions: identity, telemetry, start-up activation |
| [Zarf and Hauler](docs/design/35-zarf-and-hauler.md) | Zarf packages' checksum chain and signature, deploy actions; Hauler hauls' contents |

**Operations and patching**

| Area | What superscrubber104 checks |
|---|---|
| [VM images](docs/design/32-vm-images.md) | qcow2, VMDK, VHD, VHDX, raw and ISO read from their headers, never mounted; OVA manifests and Glance hashes and signatures |
| [Patching](docs/design/33-patching-and-feeds.md) | `superscrubber104 patch`: host inventories matched against offline OSV, dnf, Microsoft CVRF and CISA KEV feeds, then staged and confirmed |
| [Staging](docs/design/34-staging.md) | `superscrubber104 stage`: an accepted bundle placed into local repositories, re-hashed as it is copied, never pushed over the network |
| [Reports and controls](docs/design/25-reports-and-controls.md) | Markdown, HTML, JSON, CycloneDX ML-BOM and OSCAL, with a NIST SP 800-53 control matrix |

## How superscrubber104 relates to Zarf and Hauler

[Zarf](https://docs.zarf.dev/) and [Hauler](https://docs.hauler.dev/) move Kubernetes content across an air gap and deploy or serve it on the other side. Both check what they carry:
* Zarf signs each package (keylessly with Sigstore, or with a key), verifies a sha256 checksum chain offline, and generates SBOMs.
* Hauler verifies cosign signatures before saving and after loading, and keeps upstream SBOMs and attestations.

Neither inspects what is inside the artifacts, applies a site's policy, or records control-mapped evidence. superscrubber104 does not move or deploy anything; it decides whether a delivery should cross and records why. The two are used together: build and carry the package with Zarf or Hauler, and pass it through `superscrubber104 pack` and `superscrubber104 verify` on the way.

| | Zarf / Hauler | superscrubber104 |
|---|---|---|
| Package, transfer, deploy or serve | yes | carries any files; `stage` writes local repositories, never deploys |
| Signatures and checksums of what they carry | yes | Zarf's checksums and signature verified again; Hauler's cosign signatures not yet (recorded as not assessed); plus its own bundle signature and replay ledger |
| SBOM | Zarf generates (Syft); Hauler carries upstream SBOMs | generates (CycloneDX, ML-BOM) from what it inspected |
| Inspection of content: models, pickles, prompts, secrets, offline readiness | not documented | yes |
| Policy decision, approvals, evidence mapped to NIST 800-53 (or a site's own control profile) | not documented | yes |

superscrubber104 opens Zarf packages without running Zarf. It checks:
* the package's own checksum chain and signature, against keys or Sigstore identities pinned in the policy (a mismatch is final);
* the images it carries;
* the commands and host files that deploying it would run or write.

Everything inside a Zarf package, including models in image layers, goes through the same handlers as any other delivery. zstd-compressed packages, Zarf's default, are read on Python 3.14, or on 3.11 to 3.13 with the optional extra: `pip install 'superscrubber104[zstd]'`.

Hauler hauls are opened too: their image layout is checked and their images, charts and files are inspected. The cosign signatures they carry are recorded as "not assessed", because superscrubber104 does not verify cosign signatures yet. [Doc 35](docs/design/35-zarf-and-hauler.md) has the details, and records with sources what each tool does as of Zarf 1.0 and Hauler 2.1.

## Status and limits

superscrubber104 is pre-alpha: every command works end to end and is tested, but it has not yet been used for a real transfer. What it does not do is written down, area by area, at the end of each design document:

* [bundles and verification](docs/design/18-bundle-and-verification.md) (18.8), [volumes and deltas](docs/design/26-volumes-and-deltas.md) (26.4), [reports](docs/design/25-reports-and-controls.md) (25.6);
* [model packages](docs/design/19-model-packages.md) (19.5), [signatures and evaluation](docs/design/24-signatures-and-eval.md) (24.3), [data and knowledge](docs/design/22-data-and-knowledge.md) (22.5), [offline readiness](docs/design/23-offline-and-runtime.md) (23.6);
* [agents, containers and packages](docs/design/20-software-and-agents.md) (20.8), [scanners](docs/design/21-scanners-and-basics.md) (21.4): the scanner plugins have been tested against stand-ins, not the real binaries;
* [vendor trust](docs/design/27-vendor-trust.md) (27.7), [mirrors](docs/design/28-package-mirrors.md) (28.5), [more ecosystems](docs/design/29-more-ecosystems.md) (29.6), [infrastructure code](docs/design/30-infrastructure-code.md) (30.5), [IDE extensions](docs/design/31-ide-extensions.md) (31.3);
* [VM images](docs/design/32-vm-images.md) (32.6), [patching](docs/design/33-patching-and-feeds.md) (33.6), [staging](docs/design/34-staging.md) (34.4), [Zarf and Hauler](docs/design/35-zarf-and-hauler.md) (35.5 and 35.6).

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

The test suite blocks all network access. If a test needs a socket, that is a design bug. [CONTRIBUTING.md](CONTRIBUTING.md) has the guardrails and design rules every change keeps to.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
