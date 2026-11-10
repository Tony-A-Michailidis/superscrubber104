# Transfer workflow and CLI

## 14. End-to-end transfer workflow

1. **Request:** `airlock request init` creates a Transfer Request (purpose, contents, destination, approvers).
2. **Pack (low side):** `airlock pack` inventories, groups into units, runs checks, builds the SBOM/ML-BOM, signs, and emits the bundle (multi-volume if needed).
3. **Review and approve:** `airlock report` renders findings for reviewers. Approvals (and justifications for overridden blockers) are signed into the chain-of-custody log.
4. **Media transfer:** volumes written with per-volume hashes; media IDs recorded.
5. **Verify (high side):** signatures (ours and upstream), hashes, completeness, policy re-evaluation with the **high side's own pinned policy and keys**. Nothing is trusted just because the low side said so.
6. **Stage:** content is placed into high-side registries and repos (Harbor, local dnf/apt, model store, PyPI/npm mirrors, WSUS) through stager plugins.
7. **Eval (optional):** `airlock eval` confirms model behaviour.
8. **Receipt:** a signed import receipt; the audit trail is complete.

**Delta bundles:** support "everything changed since accepted snapshot X" to keep recurring transfers (mirrors, patches, model updates) small. The high side refuses deltas whose base it never accepted.


## 16. Commands (target CLI)

```
airlock keygen
airlock request init | show
airlock pack <inputs...> --request req.yaml --policy policy.yaml --key signing.key -o bundle/ [--volume-size 25G] [--delta-from <snapshot>]
airlock verify <bundle> --pubkey signing.pub --policy policy.yaml
airlock report <bundle|findings> [--format md|html|json|oscal]
airlock model inspect <path>
airlock offline-check <path>
airlock eval run|compare --set evalset.yaml --runtime <profile>
airlock stage <bundle> --target harbor|dnf|apt|pypi|npm|models|wsus ...
airlock patch inventory | plan | stage
```
Non-zero exit codes on blocking findings (CI-friendly).
