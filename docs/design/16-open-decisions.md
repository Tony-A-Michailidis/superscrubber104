# 21. Open decisions

- Final project name.
- Hosting: GitHub for visibility vs GitLab (common in high-assurance environments). Could mirror both. (A GitLab CI component is deliberately out of scope for now.)
- Signing: native ed25519 first; Sigstore/cosign key-based compatibility later; OpenSSF model-signing verification in 1d.
- SBOM engine: native parsers as the always-available baseline, Syft output merged when available (recommended).
- Package structure: phases 2 and 3 in the same package or separate packages sharing a core library.
- **Direction:** the MVP covers low-to-high. Outbound (patch inventories now; data releases later) needs its own spill and classification-marking checks.
- **Approvals and chain of custody:** inside the signed manifest vs a separate signed log; two-person sign-off for the emergency profile.
- **Media handling:** volume sizes for optical/USB media, resumable verification, delta bundles.
- **Staging targets:** plain directories first; Harbor, Pulp, Foreman/Katello, aptly, Nexus/Artifactory and WSUS as plugins.
- **Model conversion:** whether to offer sandboxed pickle → safetensors conversion at all, or only recommend it.
- **Eval tolerance:** how to set similarity thresholds across different GPU hardware on each side.
