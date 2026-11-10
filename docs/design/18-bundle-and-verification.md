# 18. Bundle format, pack and verify

> **Status: implemented** (task 4): `airlock keygen`, `airlock pack`, `airlock verify`.
> Builds on the models in [17-core-models.md](17-core-models.md). Workflow context: [§14](12-transfer-workflow-and-cli.md).

## 18.1 Bundle layout

```
bundle/
  airlock-bundle.json     marker; a pointer only, never trusted
  statement.dsse.json     DSSE envelope: in-toto Statement signed by the packer
  manifest.json           integrity inventory                     (subject of the statement)
  analysis.json           the packer's interpretation             (subject; informational)
  assessment.pack.json    the packer's findings and decisions     (subject; informational)
  request.yaml            transfer request, verbatim              (subject; optional)
  custody.jsonl           hash-chained, signed custody events     (appended after signing)
  payload/                content, stored as-is at its bundle paths
```

The payload is stored as plain files so reviewers can inspect it with ordinary tools. Multi-volume packing (1b) adds a signed volume index without changing the manifest.

## 18.2 The signed statement

An [in-toto Statement v1](https://in-toto.io/Statement/v1) in a DSSE envelope.

- **Subjects:** the sha256 of each signed file, by name.
- **Predicate** (`urn:airlock:bundle:v1alpha1`, the `Provenance` model): `bundleId`, `createdAt`, `tool`, `policyDigest` (the packer's), `source`, `destination`, `stream`, `profile`, `requestId`, `extensions`.

The manifest says *what* the content is; the statement says *which transfer* it belongs to. Keeping them apart means identical content always has the same manifest digest (the identity of a snapshot, used for delta bases), while replay, cross-enclave reuse and ordering are judged from the statement.

## 18.3 Pack

`airlock pack <inputs...> -o bundle/ --key signing.key [--policy p.yaml] [--request req.yaml]`

1. **Plan inputs.** A single directory becomes the bundle root. Several inputs are each placed under their own name, which must be unique.
2. **Walk** in name order. Links are recorded and never followed. Devices, FIFOs and sockets are recorded and reported.
3. **Copy and hash** each file in one pass (whole-file sha256 plus per-chunk sha256).
4. **Analyse** every file: all matching handlers, then archive inspection ([§18.5](#185-archive-inspection)).
5. **Check** paths (case collisions, length, size, links), conformance to the transfer request, and expired waivers.
6. **Decide** with the packing side's policy and write the manifest, analysis and assessment.
7. **Sign**, unless any finding is decided `block`. A blocked pack still writes everything, so the findings can be reviewed, but has no statement and so nothing that can be imported. A pack that only needs approval is signed: approval is the receiving side's call.
8. **Custody:** append the signed `packed` event (bundle id, manifest digest, statement digest).

A file whose name cannot be a bundle path (backslash, control character, undecodable bytes, non-NFC Unicode) is reported as `path.name.unsafe` under its escaped name and is not copied. That rule has a `block` floor, so such a pack is never signed: the content cannot be tracked reliably across filesystems, and the fix is to rename it.

## 18.4 Verify

`airlock verify <bundle> --policy p.yaml [--pubkey k.pub] [--state DIR] [--key receipt.key] [--out DIR]`

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
| 8. History | Against the ledger: not already accepted, not older than an accepted bundle of the same source and stream, clock has not gone backwards, delta base was accepted, policy change logged | `replay.*`, `delta.base.unknown`, `policy.digest.changed`, `integrity.ledger.broken` |
| 9. Decide | This side's policy, with rule floors | |
| 10. Record | Assessment written; receipt signed and appended to the ledger | |

Points worth knowing:

- **An unauthenticated statement is not acted on.** If no trusted key signed it, its subjects and provenance are discarded: content checks are reported as "not assessed" (there is no trusted manifest), no receipt is issued and nothing is added to the ledger.
- **The packer's analysis and assessment are never read.** They are covered by the signature so that reviewers can rely on them, but verification regenerates everything from the bytes.
- **Checks that cannot run say so.** Without `--state` the history checks are "not assessed"; without `identity` in the policy the destination check is "not assessed". Policy decides what that means (`notAssessed`, default `warn`).
- **Every verification of an authenticated bundle is recorded** in the ledger, whatever the verdict. Only accepted ones count as snapshots or for ordering.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Accepted |
| 1 | Blocked by policy, or approvals still required |
| 2 | Usage or configuration error (bad policy, missing key, not a bundle) |
| 3 | Integrity failure: an `integrity.*` rule failed. This is tampering or a broken trust chain, not a matter of judgement |

### Receiving-side state

`--state DIR` holds:

```
DIR/ledger.jsonl                      hash-chained log of receipts (signed if --key is given)
DIR/imports/<time>-<bundle id>/       assessment.verify.json, receipt.dsse.json (or receipt.json)
```

The receipt holds identifiers, digests, a verdict and a time, and no free text, so it is safe to send back outbound if policy allows. The custody log stays with the bundle; receiving-side events live in the ledger and are never sent back.

## 18.5 Archive inspection

Archives are **inspected, never extracted**.

- Member bytes are streamed through a hash. A member is written to a private scratch file, under a generated name, only when something must read it again (a nested archive, or a handler that recognised it). **Member names never touch the filesystem**, so path traversal, link tricks and device nodes can be reported but cannot take effect.
- Format is detected from magic bytes, never from the file name. zip (and everything built on it: wheels, JARs, VSIX, Office documents), tar, and gzip/bzip2/xz streams are read. zstd, 7z and RAR are recognised but cannot be opened by the standard library; their member checks are reported as "not assessed".
- **One budget per top-level artifact**, shared by everything nested inside it, counting bytes actually produced rather than sizes declared in headers:
  - `maxRatio`: expanded bytes per byte of the outermost archive (judged only above `ratioMinBytes`, so small, highly compressible files are not false positives)
  - `maxExpandedBytes`, `maxMembers`, `maxDepth`

  When a limit trips, inspection of that artifact stops and `archive.limit.*` is reported on the top-level artifact, with the nested archive where it stopped.
- **Member checks:** path traversal (`..`, absolute paths, drive letters, with either separator), unsafe names, links pointing outside the archive, devices and FIFOs, setuid/setgid bits, encrypted members, duplicate names (tools disagree on which copy wins), corrupt or truncated archives.
- Members are recorded in the analysis with their own hashes under references such as `vendor/lib.zip!/lib/a.py`. Hostile names are recorded escaped and flagged `unsafe`.

## 18.6 Known limits (stated honestly)

- **Truncating the custody log or ledger tail is not detectable** from the log alone. Nothing relies on the absence of a later event; anchoring the ledger head externally (for example, a counter-signed periodic checkpoint) is future work.
- **The policy file is not signed.** Its digest is in every assessment and receipt, and changes are logged, so tampering is evident afterwards but not prevented. Protect it with the host's own configuration management.
- **The local clock is trusted** for age and expiry checks. A clock earlier than the last ledger entry is detected; a clock that is merely wrong is not.
- **Pack copies the payload**, so a delivery needs its own size again in free space. Hard-linking and multi-volume output are 1b.
- **zip archives hidden behind a prefix** (self-extracting executables, llamafile-style polyglots) are not opened yet, because detection reads leading bytes. That arrives with the executable handlers.
- **Nested archive members cannot `resolve()` their neighbours** yet, so a model package inside an archive is inventoried but not assembled as a unit.
- **Approvals** are modelled but there is no `airlock approve` command yet, so a bundle whose verdict is "needs approval" cannot be cleared from the CLI. That arrives with reports (task 8).
- zstd, 7z and RAR contents are not inspected (no standard-library reader).

## 18.7 Module map

```
src/airlock/
  cli.py            keygen, pack, verify
  pack.py           pack()
  verify.py         verify()
  bundle.py         layout constants, statement build/parse
  session.py        one run: policy + rules + recorder -> assessment; exit codes
  catalog.py        built-in rules
  walker.py         input planning, deterministic scan, FileView/HeadView
  hashing.py        streaming whole-file and per-chunk hashing
  archive.py        format detection, member iteration (zip, tar), decompression
  analyzer.py       handler dispatch, archive recursion, budgets
  ledger.py         receiving-side ledger
  summary.py        terminal summary
  handlers/generic.py   media-type sniffing; the handler that accepts everything
  checks/inventory.py   paths, sizes, request conformance
  checks/transfer.py    destination, source, age, replay, ordering, delta base
```
