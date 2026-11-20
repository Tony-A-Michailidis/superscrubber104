"""What superscrubber104 contributes as evidence for each control in the built-in catalogue.

These are statements of what the tool does, from the brief's starter mapping (doc 13, section 18),
not statements that a control is satisfied: that is the assessor's judgement for a whole system.
Review each one before publishing evidence for an assessment.
"""

PROVIDED = {
    "AC-4": "Offline readiness: egress paths, cloud AI endpoints and telemetry that would carry "
    "data out; MCP servers reached over the network; the transfer's declared direction.",
    "AC-6": "Least privilege in agent permissions, MCP tool auto-approval, container users and "
    "MCP server capabilities.",
    "AU-10": "Signed statement over the manifest, analysis, assessment and request; signed "
    "approvals and overrides; signed receipts and a hash-chained ledger.",
    "CM-2": "Runtime profiles: the declared stack models were tested on, against what is "
    "delivered.",
    "CM-3": "Transfer request, approvals with written justifications, policy digest changes "
    "logged on import.",
    "CM-4": "Approval records and justifications for overridden blockers.",
    "CM-6": "Configuration findings: agent and editor settings, offline settings, container "
    "configuration, and the recommended high-side configuration.",
    "CM-7": "Least functionality: code-capable model formats, remote code, install scripts, "
    "MCP shell and capabilities, agent hooks, container privileges.",
    "CM-8": "Inventory: manifest of every file with hashes, CycloneDX SBOM/ML-BOM, unit records "
    "(models, environments, images, datasets, knowledge bases, runtime profiles).",
    "CM-10": "Licence policy applied to software, model and dataset licences and use terms.",
    "CM-11": "Packages that run code on install, agent skills and hooks, runtime fetches, "
    "approved-package lists.",
    "IA-5": "Credentials found in code, configuration, images and packages (values never "
    "recorded).",
    "MP-5": "Chain-of-custody log, per-file and per-chunk hashes, bundle descriptor.",
    "RA-5": "Vulnerability findings from a pinned scanner and database, with database age and "
    "CISA KEV marking.",
    "SA-11": "Static analysis of first-party code; evaluation sets and behavioural comparison.",
    "SA-22": "Scanner versions and minimum versions; runtime components and compatibility.",
    "SC-7": "Offline readiness: downloads, telemetry, registries and endpoints that need a route "
    "out; remote package sources.",
    "SI-2": "Known vulnerabilities and fixed versions (patch gap reporting arrives with 1c).",
    "SI-3": "Malware scan with a pinned engine and signatures; code-capable model formats; "
    "injected instructions in prompts, tool descriptions and knowledge-base documents; active "
    "content in documents.",
    "SI-7": "Integrity: hashes, our signature, publisher signatures and checksums, lockfile "
    "hashes, image digests, wheel RECORDs, unit completeness.",
    "SI-10": "Model-facing text checked for injected instructions and hidden characters.",
    "SR-3": "Supply chain: approved sources, remote sources, package and model allowlists.",
    "SR-4": "Provenance: publisher references, download records, upstream signatures and the "
    "trust level reached for each artifact.",
    "SR-10": "Static inspection results for models, images, packages, agents and data.",
    "SR-11": "Component authenticity: upstream signatures verified against pinned keys, "
    "publisher checksums, image and package digests.",
}
