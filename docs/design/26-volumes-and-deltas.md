# 26. Multi-volume and delta bundles

> **Status: implemented.** Spec: [§14](12-transfer-workflow-and-cli.md) (media transfer, delta bundles), [§16](12-transfer-workflow-and-cli.md) (`--volume-size`, `--delta-from`). Bundle format: [18](18-bundle-and-verification.md).

Neither changes what a bundle *is*. The manifest still lists the full state of the delivery with every file's hashes, so a snapshot has the same identity however it was cut or however much of it crossed this time.

## 26.1 Multi-volume bundles

```sh
airlock pack ./delivery --request request.yaml --key keys/pack.key -o bundle/ --volume-size 25GB
```

The payload is written into `volumes/0001/`, `volumes/0002/`, ... instead of `payload/`, one directory per medium:

```
bundle/
  airlock-bundle.json  statement.dsse.json  manifest.json  analysis.json  assessment.pack.json
  request.yaml  custody.jsonl
  volumes.json                  the volume index (signed)
  volumes/0001/volume.json      this volume's part of the index (not signed)
  volumes/0001/payload/...      whole files, at their bundle paths
  volumes/0001/parts/000001.part  a piece of a file too large for one volume
```

* Volumes are filled in order. A file that fits in a volume is never split: if it does not fit in the current one, it starts the next. A file larger than a volume is split across as many volumes as it needs.
* **`volumes.json`** records, for every volume, every whole file or piece it holds: which file, at which offset, its size and sha256, and where it is stored. It is one of the statement's signed files, so where every byte belongs is covered by the bundle signature.
* **`volume.json`** in each volume repeats that volume's entries and the index's digest. `airlock volume check <dir>` checks one medium against it, alone, at writing time and at every hand-over. That is a media check, not verification: it is not signed and verify never relies on it.

On the high side the volumes are found under the bundle (`volumes/NNNN`) or on media given with `--volume` (repeatable; a medium can hold a volume directory or several). A volume is recognised by its label and the index digest, so media from another bundle are ignored. Verify checks every piece against the signed index, reassembles split files in a private scratch directory, then verifies them against the manifest like any other file:

| Problem | Finding |
|---|---|
| a piece changed | `integrity.hash.mismatch` on the file, with `damagedPieces` (volume and piece), as well as the damaged chunks |
| a volume is missing | `integrity.entry.missing` on each file it held, with `missingVolumes` |
| a file on a medium that the index does not list | `integrity.entry.unexpected` |
| the index itself was altered | `integrity.statement.subject-mismatch` |

All four are final. The minimum volume size is 1 MiB.

## 26.2 Delta bundles

```sh
airlock pack ./delivery-v2 --request request.yaml --key keys/pack.key -o bundle-v2/ --delta-from bundle-v1/
airlock verify bundle-v2/ --policy policy.yaml --state /var/lib/airlock --base /srv/accepted/bundle-v1/
```

* **Pack** reads the base bundle's manifest (or a `manifest.json` given directly). A file with the same path, size and sha256 as in the base is recorded as `carried` and not copied. `Manifest.base` is the base manifest's digest. Analysis and checks still run on the full state, so completeness, units and policy are judged on everything, not only what changed. Deletions are implicit: a file in the base but not in the new manifest is simply not part of the new state.
* **Verify** refuses a delta whose base this side never accepted (`delta.base.unknown`, from the ledger, final). Each carried file is looked up in the base bundles given with `--base` (which may themselves be multi-volume) and **re-hashed against the new manifest**. The base supplies bytes, never trust: a base whose content changed since it was accepted cannot supply a carried file (`integrity.hash.mismatch`, final), and a carried file no base holds is `integrity.entry.missing`. Carried files are then inspected with everything else.
* Without `--base`, carried files are recorded as **not assessed**, never as passed. A site that always wants them checked can make that a blocker (`{rule: integrity.hash.mismatch, notAssessed: block}`).

A chain of deltas is resolved by giving every base in the chain (`--base v2 --base v1`): each carried file is taken from the first base that holds it.

## 26.3 Hard-linked payloads

`airlock pack --link` hard-links files into `payload/` instead of copying them, when the input and the bundle are on the same filesystem (it falls back to copying otherwise). The bundle then costs no extra space. The payload is hashed from the link, so what is signed is what is there; but a linked bundle shares its files with the source, so the source must not be edited until the bundle has been written to media.

## 26.4 Known limits

- Volume sizes are exact byte counts of file content; the filesystem's own overhead on the medium is not accounted for. Leave a margin.
- Verification reassembles split files in the scratch directory, which needs room for the largest split file.
- Resumable verification (picking up after an interrupted check of a very large bundle) is not implemented; chunk hashes make it possible.
- Media identifiers (serial numbers, labels) are not recorded automatically; record them in the custody log with the volume numbers.
