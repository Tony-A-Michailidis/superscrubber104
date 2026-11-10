# airlock

> **Status: pre-alpha, under active design.** Nothing here is ready for use. `airlock` is a working name.

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

## Planned usage

```console
$ airlock keygen
$ airlock pack ./delivery --request req.yaml --policy policy.yaml --key signing.key -o bundle/
$ airlock verify bundle/ --pubkey signing.pub --policy policy.yaml
$ airlock report bundle/ --format html
```

Commands exit non-zero on blocking findings, so they can gate CI pipelines.

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
