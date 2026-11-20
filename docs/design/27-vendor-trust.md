# 27. Vendor trust: OpenPGP, OS packages, checksum lists

> **Status: implemented.** Spec: [§3](03-core-concepts.md) (two layers of trust), [§4](04-artifact-coverage.md) (OS packages), [§11](11-os-patching.md) (vendor signatures). Policy schema: [17](17-core-models.md) (`trust.upstream`). Repository mirrors build on this: [28](28-package-mirrors.md).

Our bundle signature says the delivery arrived as it was packed. It says nothing about whether what was packed is what the vendor published. This doc covers that second layer for the most common vendor material: OS packages, and any file that comes with a publisher's checksum list or detached signature. Everything here is static and offline: no `gpg`, no `rpm`, no `dpkg`, no keyserver.

## 27.1 Pinned vendor keys

Vendor keys are pinned in the policy like every other trust anchor:

```yaml
trust:
  upstream:
    - name: almalinux-9
      type: gpg
      file: keys/RPM-GPG-KEY-AlmaLinux-9      # armored or binary, one or more keys
      sha256: "…"                               # the key file itself is pinned
      scope: ["package.rpm", "repo.dnf"]       # what this key may vouch for
      fingerprints: ["…"]                       # optional: only these (sub)keys
      validity: {validUntil: 2032-01-01}        # optional; also `revoked: true`
```

A key is used only within its `scope` and its validity dates (`superscrubber104/trust.py`). The archive key of one distribution can't vouch for another's packages, and a key pinned for repositories can't vouch for a loose tool download.

| Scope | Used for |
|---|---|
| `package.rpm` | the header signature inside each `.rpm` |
| `repo.dnf`, `repo.apt` | repository metadata signatures ([28](28-package-mirrors.md)) |
| `chart.helm` | Helm chart provenance files (`.tgz.prov`) |
| `file.checksums` | the signature over a checksum list (`SHA256SUMS.gpg`, clear-signed `CHECKSUM`) |
| `file.signed` | a detached signature over any file (`tool.tar.gz.asc`) |
| `vm.ova`, `vm.glance` | X.509 certificates for signed OVA manifests and Glance image signatures ([32](32-vm-images.md)) |

## 27.2 OpenPGP reader

`superscrubber104/formats/openpgp.py` reads and verifies OpenPGP (RFC 4880 / RFC 9580 v4) with `cryptography` only:

* Keys: RSA, ECDSA (P-256/384/521), EdDSA (legacy algorithm 22 and Ed25519 algorithm 27), primary keys and subkeys. The fingerprint is computed, never trusted from the file.
* Signatures: binary (type 0x00) and text (0x01, canonicalised to CRLF without trailing whitespace); detached, armored or binary; clear-signed documents (`InRelease`, Fedora-style `CHECKSUM`) with dash-escaping undone.
* MD5, SHA-1 and RIPEMD-160 signatures are refused outright. Expired signatures fail.
* A signature's creation time and lifetime are believed only from its **hashed** subpackets, which the signature covers. The unhashed area can be rewritten by anyone, so it is used only to find the issuer: a hint for choosing a key, which the verification then proves or not.
* A file can carry several signatures (publishers rotate keys, and Ubuntu signs with two). Each is tried. Signatures of versions this reader does not implement are skipped when a readable one is present.
* Truncated or malformed packets are an error (`OpenPGPError`), never a crash or a loop. Callers turn that into a finding.
* Data is hashed once, as a stream, whatever the number of pinned keys; only keys whose fingerprint matches the signature's issuer are tried.

It does **not** evaluate key certifications, user IDs, revocation signatures in the key file or the web of trust. The policy pin replaces all of that: a key is trusted because the policy names it, within its scope and dates, and rotation or revocation is a policy change the ledger records.

Validated against real AlmaLinux 9 `repomd.xml.asc` and RPMs (RSA 4096) and the Ubuntu noble `InRelease` (RSA, signed by two keys). Tampered data and the wrong key were rejected.

## 27.3 RPM packages and databases

`superscrubber104/formats/rpm.py` reads the lead, the signature header and the main header. It never reads the cpio payload, except to hash it.

| Check | Rule | Class |
|---|---|---|
| The main header matches `SHA256HEADER`; the payload matches `PAYLOADDIGEST` | `package.digest-mismatch` | final |
| A signature verifies with a key pinned for `package.rpm`: over the main header (tag 268 for RSA, 267 for ECDSA/EdDSA, 278 in rpm 6), or over header and payload together (1002, 1005, older packages) | `package.signature.invalid` (pinned key, does not hold) | final |
| | `package.signature.untrusted` (no pinned key in scope) | policy |
| The package is signed at all | `package.signature.missing` | policy |
| Install scriptlets (`%pre`, `%post`, triggers, ...) | `package.maintainer-scripts` (info) | policy |
| The delivery also holds a newer version of the same package and architecture (RPM or Debian, by `rpm` or `dpkg` version ordering) | `package.superseded` (info) | policy |

**What a signature covers.** A header signature covers the header, and the header records the payload digest, so the two checks together cover the whole package. That only holds when the header records a payload digest and it was checked. Packages built before rpm 4.14 record none: for those, a header signature says nothing about the payload. superscrubber104 then verifies the older signature over header and payload if the package has one. If it has none, the file earns **no** verification, and `package.digest-mismatch` is recorded as not assessed with that reason. A verified, fully covered package gets a `signature`-level verification naming the anchor, which the upstream trust check and the reports use like any other.

A package that cannot be read at all (truncated, damaged header) is **not assessed** for all four rules. It is not refused as altered: unreadable and altered are different findings, and a parser's failure must never be final.

Component: `pkg:rpm/<vendor>/<name>@<version>-<release>?arch=…&epoch=…`, with licence and supplier from the header.

**RPM databases** (`var/lib/rpm/rpmdb.sqlite`, `usr/lib/sysimage/rpm/rpmdb.sqlite`), as found in root filesystems and images, are read in memory from a copy, read-only and with `trusted_schema` off. Every installed package (except `gpg-pubkey` entries) becomes a component, for the SBOM and vulnerability matching. The old Berkeley DB format (`var/lib/rpm/Packages`, EL8 and older) is not parsed: it is inventoried, hashed and scanned like any unclassified file.

`rpm_vercmp` and `compare_evr` order versions exactly as `rpm` does (including `~` and `^`). They are used by the mirror and patch modules.

## 27.4 Debian packages

`superscrubber104/formats/deb.py` reads the `ar` archive and only its `control.tar.{gz,xz,zst}`. It records identity, dependencies and which maintainer scripts the package carries (`package.maintainer-scripts`).

A `.deb` has no signature of its own. Its authenticity comes from the repository: the signed `InRelease` lists the hash of `Packages`, which lists the hash of every `.deb`. That chain is checked by the mirror assembler ([28](28-package-mirrors.md)).

zstd control archives (Ubuntu since 21.10) need Python 3.14's `compression.zstd` or the optional `zstd` extra (`pip install 'superscrubber104[zstd]'`, the `backports.zstd` package). Without either, identity comes from the file name and the scripts check is recorded as **not assessed**, never silently skipped. `deb_vercmp` orders versions exactly as `dpkg` does.

## 27.5 Checksum lists and detached signatures

`superscrubber104/handlers/upstream.py` handles any file, not just packages: ISO images, cloud images, drivers, firmware and tools.

* **Checksum lists**: `SHA256SUMS`, `SHA512SUMS`, `MD5SUMS`, `CHECKSUM`, `*-CHECKSUM` (text only: coreutils' `sha256sum` and `md5sum` binaries share the names), and one-line sidecars (`file.iso.sha256`, `lib.jar.sha1`, `file.md5`), which may hold a hash alone. Both GNU (`<hash>  name`) and BSD (`SHA256 (name) = <hash>`) lines are read; the algorithm comes from the line or the hash length. Every listed file present in the delivery is hashed and compared. A difference is `upstream.checksum-mismatch` and final. Listed files that are not shipped are counted, not flagged (vendors list every edition). **MD5** can show a difference, but a match earns no verification: it proves nothing.
* **The list's signature**: clear-signed, or a sibling `.gpg`/`.asc`/`.sig`, verified with keys pinned for `file.checksums`. A verified list gives each matching file a `signature`-level verification. An unsigned list, or one whose signature cannot be tied to a pinned key, gives `checksum` level, since the list travelled with the content. Only the signed text of a clear-signed list is read.
* **Detached signatures**: `file.asc`, `file.sig` or `file.gpg` next to `file`, verified with keys pinned for `file.signed`, with the same rules and results.
* **A signature can only add trust.** One that does not verify with a pinned key is `upstream.signature.invalid` (final). One from a key nobody pinned, or one that cannot be read, is `upstream.signature.untrusted`: it is said, never passed over, and never final, because deleting the signature file would have the same effect. Sites that need signatures require them with `trust.minimumLevels`.
* **Inside archives** a list or signature cannot reach the files beside it. That is recorded as not assessed, with the advice to deliver it unpacked.

Repository signatures (`repomd.xml.asc`, `Release.gpg`, `InRelease`) are left to the mirror assembler.

## 27.6 Plumbing

Handlers can now return `verifications` on an `Inspection`, keyed by artifact, including artifacts other than the one inspected: a checksum list vouches for its targets. The analyzer collects them, and `analysis` merges them into the artifacts before the upstream trust check runs. That keeps verification facts where they belong: on the artifact they vouch for, wherever the evidence came from.

## 27.7 Tests and limits

`tests/vendor_fixtures.py` generates RSA and Ed25519 OpenPGP keys, signatures, clear-signed documents, RPMs (with header signatures, package signatures, or no payload digest), `rpmdb.sqlite` files and `.deb` packages. No vendor material is in the repository. `tests/test_vendor_trust.py` covers:

* signed, tampered (header and payload), unsigned, unpinned and out-of-scope RPMs, and what each kind of RPM signature covers;
* RPM databases, and Debian packages including an unreadable one;
* checksum lists in both formats, signed and unsigned, sidecars with a bare hash, and MD5;
* detached signatures, several signatures in one file, and unreadable ones;
* lists inside archives.

`tests/test_vendor_robustness.py` cuts short and corrupts every one of these formats (and those of docs 28 to 32) and requires that no handler crashes. It also covers the OpenPGP reader's handling of malformed packets and of times planted in the unhashed area, and the decompression limits.

Not done: v3 keys and signatures (obsolete), v6 (RFC 9580) keys, DSA keys (retired by the vendors here), IMA file signatures inside RPMs, Debian `debsig` signatures (rarely used).
