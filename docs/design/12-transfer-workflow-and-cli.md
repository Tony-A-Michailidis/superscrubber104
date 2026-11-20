# Transfer workflow and CLI

## 14. End-to-end transfer workflow

1. **Request:** `superscrubber104 request init` creates a Transfer Request (purpose, contents, destination, approvers).
2. **Pack (low side):** `superscrubber104 pack` inventories, groups into units, runs checks, builds the SBOM/ML-BOM, signs, and emits the bundle (multi-volume if needed).
3. **Review and approve:** `superscrubber104 report` renders findings for reviewers. Approvals (and justifications for overridden blockers) are signed into the chain-of-custody log.
4. **Media transfer:** volumes written with per-volume hashes; media IDs recorded.
5. **Verify (high side):** signatures (ours and upstream), hashes, completeness, policy re-evaluation with the **high side's own pinned policy and keys**. Nothing is trusted just because the low side said so.
6. **Stage:** content is placed into high-side registries and repos (Harbor, local dnf/apt, model store, PyPI/npm mirrors, WSUS) through stager plugins.
7. **Eval (optional):** `superscrubber104 eval` confirms model behaviour.
8. **Receipt:** a signed import receipt; the audit trail is complete.

**Delta bundles:** support "everything changed since accepted snapshot X" to keep recurring transfers (mirrors, patches, model updates) small. The high side refuses deltas whose base it never accepted.


## 16. Commands (target CLI)

```
superscrubber104 keygen
superscrubber104 request init | show
superscrubber104 pack <inputs...> --request req.yaml --policy policy.yaml --key signing.key -o bundle/ [--volume-size 25G] [--delta-from <snapshot>]
superscrubber104 verify <bundle> --pubkey signing.pub --policy policy.yaml
superscrubber104 report <bundle|findings> [--format md|html|json|oscal]
superscrubber104 model inspect <path>
superscrubber104 offline-check <path>
superscrubber104 eval run|compare --set evalset.yaml --runtime <profile>
superscrubber104 stage <bundle> --target harbor|dnf|apt|pypi|npm|models|wsus ...
superscrubber104 patch inventory | plan | stage
```
Non-zero exit codes on blocking findings (CI-friendly).
