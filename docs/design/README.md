# Design documents

The original project brief, split by topic. Section numbers (§N) are kept from the brief so cross-references stay stable.

| File | Brief sections | Contents |
|---|---|---|
| [01-context-and-threat-model.md](01-context-and-threat-model.md) | §1, §2 | Why the project exists, the low-to-high transfer scenario, threat model and out-of-scope items |
| [02-vision-and-principles.md](02-vision-and-principles.md) | §3, §4 | Module/phase vision, shared core, design principles |
| [03-core-concepts.md](03-core-concepts.md) | §5 | Data model concepts: Transfer Request, Bundle, Artifact, Component, Units, Policy, Finding, Evidence, Receipt |
| [04-artifact-coverage.md](04-artifact-coverage.md) | §6 | Handler interface and per-category coverage (AI, developer environment, general software/infrastructure) |
| [05-model-packages.md](05-model-packages.md) | §7 | `ModelPackage` unit: identity, weights, tokenizer, template, configs, licence, provenance |
| [06-runtime-profiles.md](06-runtime-profiles.md) | §8 | `RuntimeProfile` unit and compatibility checks |
| [07-knowledge-bases-and-agents.md](07-knowledge-bases-and-agents.md) | §9 | `KnowledgeBase` unit, MCP servers, agent hooks/skills/permissions/prompts |
| [08-offline-readiness.md](08-offline-readiness.md) | §10 | Auto-downloads, telemetry, auto-updaters, external endpoints |
| [09-behavioural-verification.md](09-behavioural-verification.md) | §11 | `airlock eval` |
| [10-vm-images.md](10-vm-images.md) | §12 | OpenStack qcow2/raw images, Glance metadata |
| [11-os-patching.md](11-os-patching.md) | §13 | `airlock patch` for AlmaLinux, Ubuntu, Windows |
| [12-transfer-workflow-and-cli.md](12-transfer-workflow-and-cli.md) | §14, §16 | End-to-end workflow, delta bundles, target CLI |
| [13-checks-and-controls.md](13-checks-and-controls.md) | §17, §18 | Check catalogue and NIST SP 800-53 / ITSG-33 control mapping |
| [14-roadmap.md](14-roadmap.md) | §15, §20 | Phases and the initial task list |
| [15-repo-layout.md](15-repo-layout.md) | §19 | Suggested package layout and `examples/` fixtures |
| [16-open-decisions.md](16-open-decisions.md) | §21 | Unresolved decisions |
| [17-core-models.md](17-core-models.md) | new | Core data models, policy schema, keys, logs and interfaces (implemented) |
| [18-bundle-and-verification.md](18-bundle-and-verification.md) | new | Bundle layout, signed statement, pack and verify steps, archive inspection, known limits (implemented) |
