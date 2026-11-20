# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Until 1.0, a minor version may change the command line, the policy schema or the bundle format (`superscrubber104/v1alpha1`).

## [Unreleased]

## [0.1.0] - 2026-11-20

The first release. superscrubber104 is pre-alpha: every command works end to end and is tested, it has been tried on one real delivery, and it has not yet been used for a real transfer.

### Transfer

- `pack` inventories, hashes, inspects and signs a delivery into a bundle; `verify` re-hashes and re-inspects it on the other side against that side's own policy, with a hash-chained ledger against replay. Multi-volume and delta bundles.
- `approve` records approvals by pinned keys; a policy blocker is overridden only by a quorum with a written justification, and integrity failures never.
- `report` renders Markdown, HTML, JSON, CycloneDX (with ML-BOM) and OSCAL, with a NIST SP 800-53 Rev 5 control matrix or a site's own control profile.
- `stage` places an accepted bundle into local repositories; `patch` matches host inventories against offline OSV, dnf, Microsoft CVRF and CISA KEV feeds.

### Inspection

- Model packages (safetensors, GGUF, pickle formats read statically and never unpickled, Keras, ONNX, Ollama, adapters), model signatures and a behavioural evaluation run through a pinned runtime.
- Agents and MCP servers, datasets, knowledge bases and notebooks, offline readiness and runtime profiles.
- Containers, Python, npm, Java, Go, Rust and .NET environments resolved against what is delivered; RPM and Debian signatures, checksum lists and OpenPGP; dnf, apt, PyPI, npm and Helm mirrors; infrastructure code; IDE extensions; VM images; Zarf packages and Hauler hauls.
- Secrets, executables, macros and PDF JavaScript in every file; ClamAV, Trivy with the CISA KEV catalogue, Semgrep and Bandit as optional, hash-pinned plugins.

### Assurance

- Fails closed: any error inside the tool is recorded as a check error or "not assessed", never an accept, and `tests/test_fail_closed.py` checks every format with values of the wrong type.
- Crosses its own airlock: [examples/self-transfer/](examples/self-transfer/README.md) packs superscrubber104, installs it on a machine with no network, and verifies the bundle it arrived in. CI runs it on every push.
- Measured at scale ([examples/scale/](examples/scale/README.md)): a 16 GiB file needs the same memory as a 1 GiB one (146 MiB); memory grows by about 5 KiB per file or archive member.
- Releases carry SHA256SUMS and are reproducible in content: rebuilding the tag gives the same files, which anyone can check ([RELEASING.md](RELEASING.md)).

[Unreleased]: https://github.com/Tony-A-Michailidis/superscrubber104/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Tony-A-Michailidis/superscrubber104/releases/tag/v0.1.0
