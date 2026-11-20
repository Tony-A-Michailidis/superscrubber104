# What airlock does, in detail

The [README](../README.md) has the summary table. This page has the detail behind each row; the design documents in [design/](design/README.md) have the full specification, and each ends with its known limits.

The commands that move a delivery:

```console
$ airlock keygen -o keys --name pack --holder build-pipeline
$ airlock pack ./delivery --request request.yaml --key keys/pack.key -o bundle/
$ airlock verify bundle/ --policy policy.yaml --state /var/lib/airlock --key keys/receipt.key --out review/
$ airlock report review/ --format html -o review/report.html
```

- `keygen` prints the snippet that pins the new key in the receiving side's policy.
- `pack` inventories, hashes, inspects and signs.
- `rules` lists every check airlock can record: what it means, its severity, the controls it is evidence for and whether anyone can override it. The same list is in [docs/rules.md](rules.md).
- `report` renders the evidence for reviewers and assessors: Markdown or a self-contained HTML page, JSON, a CycloneDX 1.6 SBOM/ML-BOM, or OSCAL assessment results, with a control matrix that shows, for each NIST SP 800-53 control, what airlock checked, what it found and what it could not assess. See [reports and control mapping](design/25-reports-and-controls.md).
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

See [examples/policy.yaml](../examples/policy.yaml) and [examples/request.yaml](../examples/request.yaml), and the [bundle format and verification steps](design/18-bundle-and-verification.md), including its list of known limits.

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

`airlock model inspect` records and checks model packages in place: safetensors, GGUF, PyTorch and other pickle-based formats (statically; nothing is ever unpickled), Keras, ONNX, Ollama stores, adapters and sentence-transformers. It checks shards against indexes, configs against tensors, tokenizers against vocabularies, chat templates, `trust_remote_code`, licences and publisher checksums. See [model packages](design/19-model-packages.md).

The same inspection covers the rest of a delivery. MCP configs, agent settings, skills and instruction files are checked for shell launchers, runtime fetches, broad permissions, literal credentials and injected instructions; MCP server code for what its tools can reach. Container images (docker save, OCI archives and layouts) are verified blob by blob, and their layers are inspected like any other archive. Python and npm lockfiles are resolved against the wheels, sdists and tarballs in the delivery, so a requirement that would need the internet on the high side, or a package that does not match its lockfile hash, is caught before transfer. See [agents, containers, packages and source](design/20-software-and-agents.md).

The data around a model is covered too: datasets (Parquet footers, Hugging Face cards and `save_to_disk` layouts, loading scripts), knowledge bases (FAISS, LangChain, Chroma, LlamaIndex, and document folders the transfer request declares as a corpus) with a scan of their documents for planted instructions and hidden text and a check that the embedding model that built each index is in the delivery, notebooks, and classic ML and MLflow models. See [data and knowledge](design/22-data-and-knowledge.md).

Every text file, including files inside container layers and packages, is searched for credentials, and documents for macros, PDF JavaScript and remote templates. Malware scanning, vulnerability scanning and static analysis use ClamAV, Trivy (with the CISA KEV catalogue), Semgrep and Bandit as optional plugins that airlock pins and checks before it trusts them; without them those checks are recorded as not assessed. `airlock plugins check` reports their state. See [scanners](scanners.md).

`airlock offline-check` reports what a delivery will try to download, report or call once disconnected (model hubs, installs, telemetry, cloud AI services, external images) and prints the configuration to set on the high side. A `RuntimeProfile` declares the stack models were tested on; airlock checks it against what is delivered and against NVIDIA's driver/CUDA table and the site's own compatibility rules. See [offline readiness and runtime profiles](design/23-offline-and-runtime.md).

Publishers' OpenSSF model signatures are verified offline (a pinned key, a CA, or Sigstore keyless against a pinned trusted root), and `airlock eval run` runs a pinned evaluation set through a pinned local runtime on each side and compares the answers, so a swapped or misbehaving model is caught. See [signatures and evaluation](design/24-signatures-and-eval.md).

OS packages and mirrors are checked as their vendors sign them, with keys pinned in the policy and limited by scope:
* RPM header and payload digests and signatures, and Debian packages;
* dnf and apt mirrors, as a chain from signed `repomd.xml` or `InRelease` to every package;
* PyPI simple, npm and Helm repositories;
* publishers' `SHA256SUMS` and detached signatures.

Stale, expired or rolled-back repository metadata is caught against the receiving side's ledger. See [vendor trust](design/27-vendor-trust.md) and [package mirrors](design/28-package-mirrors.md).

Gradle, Go, Cargo and NuGet lockfiles are resolved against the delivery with their hashes (Go's `h1:`, crate checksums, NuGet content hashes), and build-time hooks are recorded ([more ecosystems](design/29-more-ecosystems.md)). For infrastructure code ([infrastructure code](design/30-infrastructure-code.md)):
* Kubernetes and Compose workloads are checked for privileged and host access and for images by tag rather than digest;
* Helm, Terraform and Ansible dependencies must be vendored;
* Terraform providers are checked against `.terraform.lock.hcl`.

VS Code and JetBrains extensions are identified for approved lists, with telemetry and start-up activation recorded ([IDE extensions](design/31-ide-extensions.md)). VM disk images are read from their headers and never mounted ([VM images](design/32-vm-images.md)):
* qcow2, VMDK, VHD, VHDX, raw and ISO;
* incomplete, encrypted, unclean and format-confused images are caught;
* OVA manifests and Glance hashes and signatures are checked.

Large deliveries can be cut into volumes, one per medium, under one signed index (`pack --volume-size`). Recurring transfers can be deltas against a bundle the receiving side already accepted (`pack --delta-from`). See [volumes and deltas](design/26-volumes-and-deltas.md).

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

See [patching and feeds](design/33-patching-and-feeds.md). `airlock stage` places an accepted bundle into local stores (a PEP 503 index, Verdaccio storage, dnf and apt mirrors, OCI layouts, model directories, a Windows share). It re-hashes every file as it copies it, keeps a stage report, and records the event in the ledger, including a staging that failed part-way. It never pushes over the network. See [staging](design/34-staging.md).

`airlock approve` signs approvals and overrides; `airlock ledger adjust-clock` is the logged recovery path when a disconnected host's clock has drifted.
