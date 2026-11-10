# 5. Core concepts (data model)

- **Transfer Request:** a declared intent (purpose, owner, source, destination enclave, expected contents, approvers). `verify` reports anything undeclared or missing.
- **Bundle:** the signed transfer unit (optionally multi-volume): artifacts + manifest + SBOM + findings + evidence + signatures + chain-of-custody log.
- **Artifact:** one file or directory entry, with hash, size, detected type and handler.
- **Component:** an identifiable software or AI component (purl / model id + version) for the SBOM, possibly nested.
- **Units:** typed groupings with completeness rules: `ModelPackage`, `RuntimeProfile`, `PythonEnvironment` (and other language environments), `RepoMirror`, `ContainerImage`, `VMImage`, `PatchSet`, `KnowledgeBase` (RAG index + embedding model + corpus).
- **Policy:** YAML rules: allow/deny/require-approval per check, licence lists, approved packages and models, pinned upstream keys, feed maximum ages, size limits.
- **Finding:** result of one check on one artifact or unit (severity, blocker yes/no, control IDs, details).
- **Evidence:** findings plus context, rendered as human (Markdown/HTML) and machine (JSON, OSCAL stretch goal) reports.
- **Receipt:** a signed import record created on the high side after successful verification (hash-only; it can be retained or, if policy allows, sent back to close the loop).
