# 18. Bundle format, pack and verify

> **Status: implemented** (task 4): `superscrubber104 keygen`, `pack`, `verify`, `approve`, `ledger adjust-clock`.
> Builds on the models in [17-core-models.md](17-core-models.md). Workflow context: [§14](12-transfer-workflow-and-cli.md).

## 18.1 Bundle layout

```
bundle/
  superscrubber104-bundle.json     marker; a pointer only, never trusted
  statement.dsse.json     DSSE envelope: in-toto Statement signed by the packer
  manifest.json           integrity inventory                     (subject of the statement)
  analysis.json           the packer's interpretation             (subject; informational)
  assessment.pack.json    the packer's findings and decisions     (subject; informational)
  request.yaml            transfer request, verbatim              (subject; optional)
  custody.jsonl           hash-chained, signed custody events: packed, approved
  payload/                content, stored as-is at its bundle paths
```

The payload is stored as plain files so reviewers can inspect it with ordinary tools. Multi-volume bundles keep the payload in `volumes/NNNN/` with a signed volume index instead, without changing the manifest ([26](26-volumes-and-deltas.md)).

## 18.2 The signed statement

An [in-toto Statement v1](https://in-toto.io/Statement/v1) in a DSSE envelope.

- **Subjects:** the sha256 of each signed file, by name.
- **Predicate** (`urn:superscrubber104:bundle:v1alpha1`, the `Provenance` model): `bundleId`, `createdAt`, `tool`, `policyDigest` (the packer's), `source`, `destination`, `stream`, `profile`, `requestId`, `extensions`.

The manifest says *what* the content is; the statement says *which transfer* it belongs to. Keeping them apart means identical content always has the same manifest digest (the identity of a snapshot, used for delta bases), while replay, cross-enclave reuse and ordering are judged from the statement.

## 18.3 Pack

`superscrubber104 pack <inputs...> -o bundle/ --key signing.key [--policy p.yaml] [--request req.yaml]`

1. **Plan inputs.** A single directory becomes the bundle root. Several inputs are each placed under their own name, which must be unique.
2. **Walk** in name order. Links are recorded and never followed. Devices, FIFOs and sockets are recorded and reported.
3. **Copy and hash** each file in one pass (whole-file sha256 plus per-chunk sha256).
4. **Analyse** every file: all matching handlers, then archive inspection ([§18.7](#187-archive-inspection)).
5. **Check** paths (case collisions, length, size, links), conformance to the transfer request, and expired waivers.
6. **Decide** with the packing side's policy and write the manifest, analysis and assessment.
7. **Sign**, unless the pack is *refused* (a final failure, which at pack time means a file that could not be stored). A refused pack still writes everything, so the findings can be reviewed, but has no statement and so nothing that can be imported. A pack with policy blockers or findings that need approval **is** signed, and exits 1: whether to override or approve is for the approvers and the receiving side.
8. **Custody:** append the signed `packed` event (bundle id, manifest digest, statement digest).

A file whose name cannot be a bundle path (backslash, control character, undecodable bytes, non-NFC Unicode) is reported as `path.name.unsafe` under its escaped name and is not copied. That rule is final, so such a pack is never signed: the content is not in the bundle, so there is nothing an approval could apply to, and the fix is to rename it.

## 18.4 Verify

`superscrubber104 verify <bundle> --policy p.yaml [--pubkey k.pub] [--state DIR] [--key receipt.key] [--out DIR]`

Nothing is believed because the packing side said so.

| Step | What is checked | Rules |
|---|---|---|
| 1. Statement | DSSE signature by a key pinned in *this* side's policy, with the `pack` role, valid today, not revoked, allowed for the bundle's source | `integrity.signature.invalid`, `integrity.signature.untrusted-key`, `integrity.bundle.malformed`, `trust.signer.unpinned` |
| 2. Control files | Each signed file matches the statement byte for byte; nothing else is in the bundle root | `integrity.statement.subject-mismatch`, `integrity.entry.unexpected` |
| 3. Payload | Every file is re-hashed and compared with the manifest, in both directions; damaged chunks are located | `integrity.hash.mismatch`, `integrity.entry.missing`, `integrity.entry.unexpected` |
| 4. Inspection | Everything present is re-analysed with this side's handlers and limits | `archive.*`, `inventory.*`, `path.*`, `size.*` |
| 5. Request | Conformance to the (signature-covered) transfer request | `request.*` |
| 6. Custody | The log chains from a signed `packed` event for exactly this bundle | `integrity.custody.broken` |
| 7. Transfer | Destination is this enclave, source is accepted, bundle is not too old | `transfer.*`, `replay.bundle.expired` |
| 8. History | Against the ledger: not already accepted (`replay.bundle.already-accepted` when the signed statement is the one accepted before; `replay.bundle.id-reused`, critical, when a different statement carries an accepted bundle id), not older than an accepted bundle of the same source and stream, clock has not gone backwards, delta base was accepted, policy change logged | `replay.*`, `delta.base.unknown`, `policy.digest.changed`, `integrity.ledger.broken` |
| 9. Decide | This side's policy. Final rules are always `block` | |
| 10. Approvals | Signed approvals in the custody log are counted against each clearable decision ([§18.5](#185-approvals-and-overrides)) | |
| 11. Record | Assessment written, including every approval considered; receipt signed and appended to the ledger | |

Points worth knowing:

- **An unauthenticated statement is not acted on.** If no trusted key signed it, its subjects and provenance are discarded: content checks are reported as "not assessed" (there is no trusted manifest), no receipt is issued and nothing is added to the ledger.
- **The packer's analysis and assessment are never read.** They are covered by the signature so that reviewers can rely on them, but verification regenerates everything from the bytes.
- **Checks that cannot run say so.** Without `--state` the history checks are "not assessed"; without `identity` in the policy the destination check is "not assessed". Policy decides what that means (`notAssessed`, default `warn`).
- **Every verification of an authenticated bundle is recorded** in the ledger, whatever the verdict. Only accepted ones count as snapshots or for ordering.

### Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | passed | Accepted |
| 1 | blocked, needs-approval | A policy blocker stands, or approvals are outstanding. Both can be cleared with `superscrubber104 approve` |
| 2 | | Usage or configuration error (bad policy, missing key, not a bundle) |
| 3 | refused | An integrity or authenticity check failed (tampering, bad signature, replay, wrong enclave), or a block on a rule the policy marks `overridable: false` stands. Nothing can override it; do not retry, investigate |

### Receiving-side state

`--state DIR` holds:

```
DIR/ledger.jsonl                      hash-chained log of receipts (signed if --key is given)
DIR/imports/<time>-<bundle id>/       assessment.verify.json, analysis.verify.json, request.yaml,
                                      receipt.dsse.json (or receipt.json); superscrubber104 report reads it
```

The receipt holds identifiers, digests, a verdict and a time, and no free text, so it is safe to send back outbound if policy allows. The custody log stays with the bundle (approvals made on either side are appended to it); the ledger stays on the receiving side. Neither is sent back.

## 18.5 Approvals and overrides

The rules are in [17 §17.7](17-core-models.md#177-policy). In practice:

```console
$ superscrubber104 verify bundle/ --policy policy.yaml --out review/
BLOCK    model.pickle.dangerous-import  [3f9c0a1b2c3d4e5f]
         models/legacy/weights.pt: Pickle imports a dangerous callable
         approvals: 0 of 2
verdict: BLOCKED - a policy blocker stands; it can be overridden by an approval quorum

$ superscrubber104 approve bundle/ --key keys/alice.key --assessment review/assessment.verify.json \
    -f 3f9c0a1b2c3d4e5f -j "Vendor model, no safetensors build exists. Loaded only in the sandboxed converter."
$ superscrubber104 approve bundle/ --key keys/bob.key   ... (a second person)

$ superscrubber104 verify bundle/ --policy policy.yaml
OVERRIDE model.pickle.dangerous-import  [3f9c0a1b2c3d4e5f]
         approvals: 2 of 2 (alice, bob)
verdict: PASSED
```

- `superscrubber104 approve` refuses, before signing anything, what could never count: the packer's own key, a final finding, a finding that needs no approval, an empty justification, or an assessment that belongs to a different manifest.
- Approvals can be made on the packing side (against the packer's assessment, the default) or on the receiving side (against that side's `assessment.verify.json`). Either way, only the verifying side's policy decides whether they count.
- An approval that is not counted is listed with the reason (unknown key, wrong role, expired or revoked key, the packer, a different manifest, a finding that has changed, a final finding).
- If the custody log is damaged, no approval in it is counted.

## 18.6 Clock drift and recovery

Age, expiry and ordering checks depend on the local clock, and clocks drift on disconnected systems. Three things keep that from locking out the receiving side on a bad day.

1. **Tolerance.** `transfer.clockTolerance` (default 10 minutes) is allowed before anything is reported.
2. **Early warning.** A bundle whose creation time is *later* than this system's clock, beyond the tolerance, is reported as `replay.clock.skew` (a warning). It usually means this host's clock is behind, and it shows up long before any regression.
3. **A logged recovery path.** If the clock is earlier than the latest time in the ledger, beyond the tolerance, every import is refused with `replay.clock.regression` (final). The ledger's mark is the *maximum* time recorded, so retrying does not make it go away.

To recover:

- **If the clock is wrong now,** correct it. Nothing else is needed.
- **If the clock was wrong earlier** (it ran fast, imports were recorded with future times, and it has since been corrected), record that:

  ```console
  $ superscrubber104 ledger adjust-clock --state /var/lib/superscrubber104 --key keys/receipt.key \
      --reason "RTC battery replaced; clock ran 3 days fast from 2026-11-01"
  ```

  This appends a signed, hash-chained `clock-adjusted` event holding the reason, the previous high-water mark and the new clock reading, and restarts the mark from there. It never happens implicitly, it cannot be done without leaving that record, and the next import lists it as `replay.clock.adjusted` so the adjustment and its reason appear in that import's evidence. The command does nothing if the clock is not behind the ledger.

The adjustment does not relax anything else: bundles are still checked for age, replay and ordering against the corrected clock.

**If the ledger itself is lost or damaged,** `integrity.ledger.broken` refuses every import that uses that state directory. Restore the ledger from backup. Starting a new state directory also works but discards the record of what was accepted, so deltas against earlier snapshots will be refused and replays of earlier bundles will not be noticed; do that only as a recorded decision. Back the state directory up with the rest of the host.

## 18.7 Archive inspection

Archives are **inspected, never extracted**.

- Member bytes are streamed through a hash. A member is kept only when something must read it again (a nested archive, or a handler that recognised it): in memory up to 1 MiB, otherwise in a private scratch file under a generated name. Every text member is kept, because the secrets scan reads it. **Member names never touch the filesystem**, so path traversal, link tricks and device nodes can be reported but cannot take effect.
- Format is detected from magic bytes, never from the file name. zip (and everything built on it: wheels, JARs, VSIX, Office documents), tar, and gzip/bzip2/xz streams are read. zstd streams are read on Python 3.14 and later (`compression.zstd`, with the same budget), and before 3.14 with the optional `zstd` extra (`pip install 'superscrubber104[zstd]'`, the `backports.zstd` package), which has the same API; without either they are recognised but not opened, and their member checks are reported as "not assessed" with advice. 7z and RAR are recognised but cannot be opened by the standard library; their member checks are "not assessed".
- **One budget per top-level artifact**, shared by everything nested inside it, counting bytes actually produced rather than sizes declared in headers:
  - `maxRatio`: expanded bytes per byte of the outermost archive (judged only above `ratioMinBytes`, so small, highly compressible files are not false positives)
  - `maxExpandedBytes`, `maxMembers`, `maxDepth` (5 by default: a Zarf package holds image layers, which hold archives of their own)

  When a limit trips, inspection of that artifact stops and `archive.limit.*` is reported on the top-level artifact, with the nested archive where it stopped.
- **Member checks:** path traversal (`..`, absolute paths, drive letters, with either separator), unsafe names, links pointing outside the archive, devices and FIFOs, setuid/setgid bits, encrypted members, duplicate names (tools disagree on which copy wins), corrupt or truncated archives.
- Members are recorded in the analysis with their own hashes under references such as `vendor/lib.zip!/lib/a.py`. Hostile names are recorded escaped and flagged `unsafe`.

## 18.8 Known limits (stated honestly)

- **Truncating the custody log or ledger tail is not detectable** from the log alone. Nothing relies on the absence of a later event; anchoring the ledger head externally (for example, a counter-signed periodic checkpoint) is future work.
- **The policy file is not signed**, and so neither are the waivers in it. Its digest is in every assessment and receipt, and changes are logged, so tampering is evident afterwards but not prevented. Whoever can edit the receiving side's policy can change what is blocked; protect it with the host's own configuration management. Final rules are out of the policy's reach either way.
- **The local clock is trusted** for age and expiry checks. A clock behind the ledger, or behind a bundle's creation time, is detected ([§18.6](#186-clock-drift-and-recovery)); a clock that is wrong in a way neither reveals is not.
- **Pack copies the payload**, so a delivery needs its own size again in free space. `--link` hard-links instead, and `--volume-size` writes media-sized volumes ([26](26-volumes-and-deltas.md)).
- **zip archives hidden behind a prefix** (self-extracting executables, llamafile-style polyglots) are not opened yet, because detection reads leading bytes. That arrives with the executable handlers.
- **Nested archive members cannot `resolve()` their neighbours** yet, so a model package inside an archive is inventoried but not assembled as a unit.
- **Approvals are appended to the bundle's custody log in place**, so the bundle must be on writable storage when someone approves on the receiving side.
- 7z and RAR contents are not inspected (no standard-library reader), nor are zstd contents before Python 3.14 without the `zstd` extra.

## 18.9 Module map

```
src/superscrubber104/
  cli.py            keygen, pack, verify, approve, ledger adjust-clock
  pack.py           pack()
  verify.py         verify()
  bundle.py         layout constants, statement build/parse
  session.py        one run: policy + rules + recorder -> assessment; exit codes
  catalog.py        built-in rules
  walker.py         input planning, deterministic scan, FileView/HeadView
  hashing.py        streaming whole-file and per-chunk hashing
  archive.py        format detection, member iteration (zip, tar), decompression
  analyzer.py       handler dispatch, archive recursion, budgets
  ledger.py         receiving-side ledger, high-water mark, clock adjustments
  approvals.py      approve(); counting approvals against decisions
  summary.py        terminal summary
  handlers/generic.py   media-type sniffing; the handler that accepts everything
  checks/inventory.py   paths, sizes, request conformance
  checks/transfer.py    destination, source, age, replay, ordering, delta base
```
