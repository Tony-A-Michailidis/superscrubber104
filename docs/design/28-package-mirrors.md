# 28. Package mirrors

> **Status: implemented.** Spec: [§4](04-artifact-coverage.md) (package mirror subsets, Linux repos), [§11](11-os-patching.md) (vendor signatures, downgrade and freeze protection). Builds on [27](27-vendor-trust.md) (pinned keys, OpenPGP, RPM/DEB).

Mirrors are the bulk of most recurring transfers, and the easiest place to slip something in: a package added to a directory, an index edited to match it, or an old snapshot replayed so that security updates are quietly undone. A mirror is checked as a **unit** (`repo-mirror`), as a chain from signed metadata to every package.

| Format | Metadata (signed) | Index | Content | Root of the unit |
|---|---|---|---|---|
| dnf / yum | `repodata/repomd.xml` + `repomd.xml.asc` | `repodata/*primary.xml[.gz/.xz/.bz2/.zst]` | `.rpm` | the directory above `repodata/` |
| apt | `dists/<suite>/InRelease`, or `Release` + `Release.gpg` | `dists/<suite>/<component>/binary-<arch>/Packages[.xz/.gz/.bz2]` | `.deb` | the directory above `dists/` (all suites together) |
| PyPI simple (PEP 503 HTML, PEP 691 JSON) | none | `simple/<project>/index.html` or `index.json` | wheels, sdists | the directory above `simple/` |
| npm registry storage (Verdaccio layout) | none | `<name>/package.json` packuments | `.tgz` | the storage directory |
| Helm repository | `index.yaml` (unsigned) | the same file | chart `.tgz`; optional `.tgz.prov` | the directory holding `index.yaml` |

## 28.1 The chain

The mirror handler (`airlock/handlers/mirrors.py`) checks every link where it finds it:

* **Metadata.** The signature is checked against keys pinned for `repo.dnf` or `repo.apt` ([27.1](27-vendor-trust.md)). The outcome is one of verified, `repo.metadata.signature.invalid` (a pinned key that does not hold: final), `repo.metadata.signature.untrusted` (a key nobody pinned) or `repo.metadata.unsigned`. Every index it lists that is in the delivery is hashed and compared: `repo.metadata.digest-mismatch` is final. `Valid-Until` in the past is `repo.metadata.expired`.
* **Index.** Every package it lists that is in the delivery is compared with the listed hash: `repo.content.digest-mismatch` is final. Large indexes are streamed (AlmaLinux AppStream's `primary.xml` is about 400 MB uncompressed). When `Packages` is shipped in several compressions, one is read; the others are recorded as `sameAs`. Each still has to match `Release`.
* **Helm provenance.** A `.prov` file is a clear-signed statement of a chart's sha256, verified against keys pinned for `chart.helm`. It reuses the `upstream.*` rules ([27.5](27-vendor-trust.md)).
* **Inside an archive** (a mirror delivered as a tarball) an index cannot reach the packages it lists. The chain is recorded as **not assessed** for that metadata, with the advice to deliver the mirror as a directory. Nothing is skipped silently.
* **MD5-only indexes.** A listed MD5 can show that a package differs, but a match earns no verification.
* **Limits.** Indexes are decompressed through a cap (8 GiB expanded). Metadata that does not parse is `repo.metadata.malformed`; the index beside it is then on its own and is reported as `repo.metadata.unlisted`.

The repo-mirror assembler (`airlock/units/repo_mirror.py`) joins the links per root:

* An index is **chained** when metadata in the same mirror lists it and the hash matched. A dnf or apt index that nothing vouches for is `repo.metadata.unlisted`.
* A package listed by a chained index under verified metadata gets a `repo-metadata` verification at **signature** level. It names the anchor and signer, so `trust.minimumLevels` can require it, exactly as it can for a signed RPM. Any other listed package whose hash matched gets `repo-index` at **checksum** level. Chained indexes and the metadata file get the signature level too.
* Listed packages that are absent are `repo.content.missing` (low: normal for a curated subset; count and sample recorded). Entries with absolute URLs are `repo.content.external`.
* Packages under the root that no index lists are `repo.content.unlisted`. This is decided in `analysis.finish`, once every artifact is known. A mirror nested inside another keeps its own packages: they are judged by the inner mirror only. Such packages are either dead weight (`dnf` and `apt` will not see them) or were added after the metadata was made.

A curated subset made by re-running `createrepo_c` or `dpkg-scanpackages` on the low side drops the vendor signature. It is then reported as unsigned, and the individual RPM signatures ([27.3](27-vendor-trust.md)) remain the proof of origin. For apt there is no per-package signature, so a re-generated apt subset can only reach checksum level unless the site re-signs it with a key the receiving policy pins for `repo.apt`.

## 28.2 Freshness and rollback

Each metadata file gives a **snapshot**: a repository identity and a time.

| Format | Identity | Time |
|---|---|---|
| dnf | `dnf:<root>` | the newest `<timestamp>` in `repomd.xml` |
| apt | `apt:<Origin>/<Suite>` | `Date` |
| Helm | `helm:<root>` | `generated` |

* **Stale.** `freshness.mirrors` in the policy sets a maximum age per format, with `default` as the fallback. Older metadata is `repo.metadata.stale`. With no limit set, no age check is made.

  ```yaml
  freshness:
    feeds: { default: 7d }
    mirrors: { default: 30d, apt: 14d }
  ```

* **Rollback.** Unit attributes carry the snapshots, and so does the receipt (`Receipt.snapshots`). The receiving side's ledger therefore knows the newest snapshot it has accepted for each repository. On `airlock verify --state`, a snapshot older than that is `repo.metadata.rollback` (high): a replayed mirror would undo updates already imported. Without a ledger the check is recorded as not assessed.

## 28.3 Unit attributes

`format`, `snapshots`, `signatures` (status and anchor per metadata file), `indexes`, `chainedIndexes`, `packages` (listed and present), `verifiedPackages` (at signature level), `missing`, `external`.

## 28.4 Validation and tests

Checked against the real AlmaLinux 9 repository (`repomd.xml` and its signature, a 55 MB `primary.xml.gz` listing 3,802 packages, two RPMs) and Ubuntu noble (`InRelease`, `main/binary-amd64/Packages.gz`, `hello`). Both chains verified to signature level with the pinned vendor keys. `tests/test_mirrors.py` covers each format, plus:

* tampered and re-compressed indexes;
* unsigned, untrusted and invalid metadata;
* `Release` with `Release.gpg`;
* expiry, staleness, missing, unlisted and external entries;
* rollback across two imports with a ledger;
* a mirror inside an archive, a mirror inside a mirror, and metadata that does not parse.

## 28.5 Limits

* Not read: `filelists`, `other`, `modules.yaml` and `updateinfo.xml` (the last is for `airlock patch`). Their hashes are still checked against `repomd.xml`. Also not read: apt `Contents`, `i18n` and `by-hash`.
* `xml:base` in `primary.xml` (packages served from another host) is not followed.
* zstd-compressed indexes need Python 3.14 or the `zstd` extra. Without either, the index is reported as malformed with the reason given.
* Conda channels, Maven repositories, Go module proxies, Cargo registries and NuGet feeds are covered with their ecosystems ([29](29-more-ecosystems.md)).
