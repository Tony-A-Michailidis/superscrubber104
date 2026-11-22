# 35. Zarf and Hauler

> **Status: research done; Zarf packages are inspected (§35.5); Hauler hauls are inspected without verifying their cosign signatures (§35.6).** Facts below are from the projects' own documentation, release notes and source code, and from one real Zarf package examined offline (§35.2 and §35.5). Sources are in §35.8. Where a source was secondary or a fact could not be confirmed, that is said.

Zarf and Rancher Government Hauler are open-source tools for moving content into disconnected environments. They overlap with superscrubber104's transport side. Their job is to move content and deploy it. superscrubber104's job is to inspect content, decide by policy whether it may cross, and record evidence of why. This document records what they do as of November 2026, so that superscrubber104 can work with them rather than duplicate them, and describes how superscrubber104 inspects their packages.

## 35.1 Zarf (1.0)

Zarf began at Defense Unicorns, was contributed to the OpenSSF in 2024, and reached 1.0 in November 2026 ([OpenSSF announcement](https://openssf.org/blog/2026/11/09/announcing-zarf-1-0-security-and-stability-for-airgap-software-delivery/); GitHub lists v1.0.0 on 10 November and v1.0.1 on 11 November). It packages what a Kubernetes deployment needs and deploys it on the disconnected side.

| Area | What Zarf does |
|---|---|
| **Package** | One tarball, zstd-compressed unless `metadata.uncompressed` is set (`.tar` or `.tar.zst`), defined by `zarf.yaml`. Kinds: `ZarfPackageConfig` and `ZarfInitConfig` (the init package bootstraps a registry, git server, mutating agent and optionally K3s). Packages can be split for small media (`--max-package-size`) or published to an OCI registry. |
| **Content** | Per component: container images, Helm charts, Kubernetes manifests, files placed on the host, git repositories, and **actions**: shell commands run on create, deploy and remove. Version 1.0 introduces the v1beta1 schema (`apiVersion: zarf.dev/v1beta1`; values replace variables; `documentation` becomes `attachments`). |
| **Integrity** | `checksums.txt` lists the sha256 of every file in the package; `zarf.yaml` records the sha256 of `checksums.txt` (`aggregateChecksum`). Zarf verifies each file against these on verify and deploy. |
| **Signing** | The signature covers `zarf.yaml` and therefore, through the checksums, the whole package. It is stored as `zarf.bundle.sig`, a Sigstore bundle. Signing can use a local key, a cloud KMS (AWS, GCP, Azure, Vault) or keyless Sigstore (Fulcio certificate, Rekor log entry). Verification runs **offline**: the binary embeds a Sigstore trusted root, and keyless bundles carry a Rekor inclusion proof. `zarf package deploy --verify` aborts on a failed verification. The 1.0 init packages are signed keyless by Zarf's release workflow. |
| **SBOM** | Syft-generated SBOMs (Syft JSON) for images, files and data injections, made at package creation and stored in the package; `zarf package inspect sbom` extracts them. `--skip-sbom` turns this off. |
| **Vulnerabilities** | Not built in. The docs describe scanning a package with Grype, which reads the embedded SBOMs, and gating CI with Grype's `--fail-on`. |
| **Policy** | None built in beyond signature verification and checksums. |
| **Differential packages** | `zarf package create --differential <previous package>` leaves out images, repositories and OCI skeleton components already present in the reference package. The package version must change. `zarf.yaml` records the reference version. |
| **Deploy** | `zarf package deploy` pushes images and repositories into the in-cluster registry and git server, installs charts and manifests, places files and runs actions. |

Zarf ships AI workloads into disconnected environments. Defense Unicorns' LeapfrogAI is built as Zarf packages ([LeapfrogAI repository](https://github.com/defenseunicorns/leapfrogai)).

## 35.2 What a real Zarf package contains

The published `zarf-init-amd64-v1.0.1.tar.zst` (392 MiB) was downloaded to the scratchpad and read statically: listed, hashed and parsed, never extracted to disk and never run. Its sha256 matches the release's `checksums.txt`.

```
checksums.txt            sha256 of every file below, except zarf.yaml and zarf.bundle.sig
zarf.yaml                the definition; metadata.aggregateChecksum = sha256(checksums.txt)
zarf.bundle.sig          Sigstore bundle v0.3: a message signature over zarf.yaml
components/<name>.tar    one tar per component:
                           <name>/charts/<chart>-<version>.tgz
                           <name>/values/<chart>-<version>-<n>     (values files, no extension)
                           <name>/manifests/<name>-<n>.yaml
                           <name>/files/<n>/<file>                 (n = index in zarf.yaml files)
images/                  one OCI image layout for all images: oci-layout, index.json, blobs/sha256/
sboms.tar                Syft JSON per image and per component with files
documentation.tar        attachments
```

What was checked, using superscrubber104's existing primitives in a throwaway script:

* `aggregateChecksum` equals the sha256 of `checksums.txt`. All 35 listed files match; no file is unlisted except `zarf.yaml` and `zarf.bundle.sig`, which `build.provenanceFiles` names as added after the checksums were made.
* The signature verifies over the exact bytes of `zarf.yaml`. The bundle's certificate chains to a Fulcio CA in Sigstore's public trusted root. The Rekor signed entry timestamp verifies with the pinned log key. The `hashedrekord` log entry records this artifact hash and this signature. The certificate was valid at the logged time. Its identity is `https://github.com/zarf-dev/zarf/.github/workflows/release.yml@refs/tags/v1.0.1`, issued by `https://token.actions.githubusercontent.com`.
* Changing one byte of `zarf.yaml` makes the signature fail.
* Files fetched from the internet at create time carry a `shasum` in `zarf.yaml` (the K3s binary, its airgap image tarball, the injector); all three match the files in the component tars. Files from the package's own source tree carry none.
* Image names in `zarf.yaml` are written short (`library/registry:3.1.1`), while `images/index.json` uses full references (`docker.io/library/registry:3.1.1`). A cross-check must normalise them.
* The K3s component's actions run on the deploying host: they reload systemd, enable and start K3s, and on RHEL variants disable `firewalld`. Its description reads `*** REQUIRES ROOT (not sudo) ***`.

**Not confirmed on real data:**

* This init package's `zarf.yaml` has **no** `apiVersion` and uses the v1alpha1 field names (`files[].shasum`, `target`, `###ZARF_TEMP###`), despite the 1.0 release note "default to v1beta1 init package". The v1beta1 Go types move `aggregateChecksum` from `metadata` to `build`, rename `shasum` to `checksum` (`<algorithm>:<hex>`) and `target` to `destination`, and record the differential base as `build.differential.fromVersion`. A v1beta1 package has not been examined; any reader must handle both.
* Split packages, differential packages, key- and KMS-signed packages, and packages with git repositories or data injections have not been examined.

## 35.3 Hauler (2.1)

Hauler is maintained by Rancher Government Solutions. The latest stable release on its releases page, when checked on 16 November 2026, was v2.1.2. It collects artifacts into a local store, saves the store as one archive (a "haul"), and loads and serves it on the disconnected side.

| Area | What Hauler does |
|---|---|
| **Content** | Container images, Helm charts and files, from registries, Helm repositories and URLs. The source also defines directories and git repositories as content kinds. Declarative manifests (`hauler-manifest.yaml`) or CLI. |
| **Store and haul** | The store holds every artifact as OCI content ("an OCI layout compatible form"), with a `kind` annotation per entry (`dev.hauler/image`, `dev.hauler/sigs`, `dev.hauler/atts`, `dev.hauler/sboms`, ...). `hauler store save` writes `haul.tar.zst` by default, or gzip when the filename asks. Since 2.1.0 hauls carry an `oci-layout` marker and can be chunked (`haul.tar.zst.001`, ...). |
| **Integrity** | Content-addressed blobs. `hauler store info --check` validates each blob's presence, size and digest (2.1.0). There is no package-level signed manifest. |
| **Signing** | Cosign verification with a key or a keyless identity before content is saved, and again after a haul is loaded. A failed verification aborts the run (2.1.0). Signatures, attestations and SBOMs that exist upstream are kept with each artifact (2.1.1). |
| **SBOM, vulnerabilities, policy** | Upstream SBOMs and attestations are carried. Nothing in the docs or recent release notes describes generating SBOMs, vulnerability scanning or policy. |
| **Delivery** | `hauler store serve registry` and a fileserver, or copy into an existing registry. |

No public haul was found to examine. The format above is from the docs, release notes and the source's constants, not from a real archive.

## 35.4 Overlap and difference

Both tools overlap with superscrubber104, and in places do more than it does:

* **Integrity and signing.** Zarf's checksum chain and Hauler's per-artifact cosign checks overlap with superscrubber104's bundle signature. Zarf's offline keyless verification is close to what superscrubber104 does for model signatures.
* **Splitting and deltas.** Zarf split packages and differential packages, and Hauler's chunked hauls, overlap with superscrubber104's multi-volume and delta bundles.
* **Delivery.** Both deploy or serve content; `superscrubber104 stage` only writes files and indexes.
* **SBOM and scanning.** Zarf generates SBOMs, and Grype on them gives a vulnerability gate, much as superscrubber104's Trivy plugin does.

What superscrubber104 adds, which neither documents:

* **Inspection of what is inside.** Model formats read without loading them, pickle opcodes, `trust_remote_code`, chat templates, embedding-model consistency, injected instructions in corpora and agent configuration, secrets, active content in documents, offline readiness.
* **An independent decision on the receiving side.** Re-hashing and re-inspecting with the receiving side's own policy and keys. Integrity rules that nothing can override. Approval quorums with written justifications. A replay ledger.
* **Evidence for an assessment.** Every check mapped to NIST SP 800-53 / ITSG-33 controls, rendered as OSCAL and CycloneDX, with checks that could not run recorded as not assessed.
* **Content beyond Kubernetes.** VM images, OS patch planning, IDE extensions, bare-metal GPU stacks. (Zarf also places host files and runs host actions; its centre is still a Kubernetes cluster.)

They are complementary: Zarf or Hauler builds and moves the package, and superscrubber104 inspects it before it is allowed to cross and again on arrival. The useful work for superscrubber104 is to read their packages as well as it reads anything else.

## 35.5 Zarf packages (as built)

`handlers/zarf.py`, kind `zarf.package`, unit `zarf-package`. The owner's decisions on the review questions are in §35.7.

### Two changes in the core

1. **zstd.** On Python 3.14 and later, zstd joins gzip, bzip2 and xz in the archive walker (`compression.zstd`, standard library, under the same expansion budget). Before 3.14, the optional `zstd` extra (`pip install 'superscrubber104[zstd]'`, the `backports.zstd` package) provides the same module. Without either, a zstd archive is still recorded with its contents **not assessed**. The reason recorded says to use 3.14 or the extra, or to build the package with `metadata.uncompressed: true` or decompress it before packing. Zarf's checksums cover the members, not the compressed archive, so a decompressed package is still fully verifiable. The core has no new dependency.
2. **Images in an OCI layout inside an archive.** The container handler's layout checks run over any store (`containers.MemoryStore`, `inspect_store`), not just a directory or an image tar:
   * index to manifests to configs and layers;
   * every digest equal to its name;
   * every referenced blob present.
   The Zarf handler fills a store from its own streaming pass.

The default `limits.archive.maxDepth` rose from 4 to 5. A package holds image layers, and the layers hold archives of their own (wheels, model zips).

### The handler

**Recognised** by name (`zarf-package-*.tar[.zst]`, `zarf-init-*.tar[.zst]`), with a tar or zstd header. It is a Zarf package only if `zarf.yaml` is in it; otherwise it is left to the other handlers. Content cannot decide earlier: Zarf writes `zarf.yaml` last, and packages are usually zstd. A package under another name is still walked and its content inspected, and after the walk any archive with `zarf.yaml` and `checksums.txt` at its root that no Zarf check covered gets every Zarf rule recorded as not assessed, with the name to give it (`checks/renamed.py`). A source tree with only a `zarf.yaml` is not a package and gets nothing.

**One streaming pass** over the archive, decompressed through `archive.capped` within the archive limits: `maxRatio` (judged above `ratioMinBytes`) and `maxExpandedBytes`, the same rule as the archive walk. A package that would expand further is not assessed:
* hashes every member, and every file inside each `components/<name>.tar`, with sha256;
* keeps only `zarf.yaml`, `checksums.txt` and `zarf.bundle.sig` (up to 16 MiB each), plus the image index, manifests and configs (JSON blobs up to 4 MiB, 64 MiB in all).

A package is read once by this handler, and once more by the archive walk that inspects its contents.

Then, in order:

1. **Definition.** `zarf.yaml` is read with the untrusted YAML loader.
   * Schemas: no `apiVersion` or `zarf.dev/v1alpha1` (Zarf 1.0's own packages), or `zarf.dev/v1beta1`.
   * Field locations that differ between the two are handled: the aggregate checksum in `metadata` or `build`; images as strings or objects; file checksums as `shasum` or `checksum: sha256:…`; targets as `target` or `destination`; differential base as `differentialPackageVersion` or `differential.fromVersion`.
   * Any other schema, or a definition that cannot be read, makes every Zarf rule **not assessed**, never a failure.
2. **Checksum chain.** These are records that travelled with the content, so all are **final**.
   * `zarf.package.checksum-mismatch`: the sha256 of `checksums.txt` differs from the aggregate checksum, or a listed file differs from its line. A duplicated member name counts if any copy differs.
   * `package.member.conflicting-copies` (critical, final): the package holds one path twice with different content, `zarf.yaml` included. Its signature and checksums vouch for one copy, extraction keeps the last, so nothing in the package is given a trust level. The components of every copy of `zarf.yaml` are still checked, so deploy actions hidden in a second copy are reported. Hauler hauls get the same rule for any path in their layout.
   * `zarf.package.incomplete`: a listed file is absent, or the definition has an aggregate checksum but there is no `checksums.txt`.
   * `zarf.package.unlisted` (high): a file is neither listed nor among the provenance files (`zarf.yaml`, `checksums.txt`, `zarf.bundle.sig`, and whatever `build.provenanceFiles` names, which the signature covers).
   * A package with no `checksums.txt` and no aggregate checksum has these rules recorded as not assessed.
3. **Signature.** `zarf.bundle.sig` is verified against `trust.upstream` entries with scope `zarf.package`:
   * keyless: `type: sigstore` with the trusted root and the identities and issuers it accepts;
   * a key or a CA: `type: x509`, PEM.

   `formats/sigstore.py` reads message-signature bundles, the signature being over the bytes of `zarf.yaml`. For keyless signatures, the log entry is a `hashedrekord` that must record both the hash of `zarf.yaml` and this signature.

   Outcomes:
   * The signature does not hold, or the bundle's message digest is not the hash of `zarf.yaml`: `upstream.signature.invalid`, final.
   * It holds for no key, CA or identity the policy pins, or the bundle cannot be read: `upstream.signature.untrusted`.
   * `build.signed: true` with no signature file: untrusted, with status `missing`.

   A package whose signature and flag were both removed and whose checksums were recomputed is indistinguishable from an unsigned one. It is recorded as `unsigned` with checksum-level trust, so a site that needs signed packages says so with `trust.minimum`:

   ```yaml
   trust:
     minimum:
       zarf.package: signature
   ```

   The package file itself carries the trust its chain establishes: signature level when the signature is verified and the checksum chain holds, checksum level when only the chain holds, none when either is broken or the package holds conflicting copies. A Hauler haul carries none, because its cosign signatures are not verified yet, so `hauler.haul: signature` fails every haul.
4. **Trust levels.** `zarf.yaml` gets a signature-level verification when the signature verifies. Every file the chain binds also gets one: the aggregate binds `checksums.txt`, which binds the rest. An unsigned but consistent package gives those files checksum level. A broken chain gives nothing.
5. **Images.** The container checks run over `images/`. Their findings and the `container-image` unit are rooted at `images/index.json`.

   Every image a component names must appear in the index's `org.opencontainers.image.ref.name` annotations, after normalisation: `library/registry:3.1.1` becomes `docker.io/library/registry:3.1.1`. A missing image is `zarf.package.incomplete`, unless the package is differential (see 8).
6. **Component files.** A `files` entry with a recorded sha256 is compared with the one file stored under `<component>/files/<index>/`. A mismatch is `zarf.package.checksum-mismatch` (final), and a missing file or component tar is `zarf.package.incomplete`.

   Everything else a component declares must be in its tar too, at the paths Zarf writes (checked against the 1.0.1 init package, whose charts, values files and manifests all match): `charts/<chart>-<version>.tgz`, `values/<chart>-<version>-<n>` for each values file, `manifests/<manifest>-<n>.yaml` for each manifest file and `kustomization-<manifest>-<n>.yaml` for each kustomization, something under `repos/` when there are git repositories, and `data/<n>/` for each data injection. Anything absent is `zarf.package.incomplete`. Data injections, which copy files into running pods at deploy time, are also listed per component in the evidence (source, namespace, selector, container, path).

   Entries with `extractPath`, or whose source was a directory, are not compared: their recorded checksum is of something else. A component tar that cannot be read leaves the comparison not assessed.

   Files placed outside `###ZARF_TEMP###` are listed under `zarf.component.host-files` (low), with target, executable flag and symlinks.
7. **Actions.** Every `onDeploy` and `onRemove` command is reported under `zarf.component.actions`, always medium, so it needs approval. Each entry gives the component, event, stage, command text and description. `wait` actions are not commands and are not listed. `onCreate` commands ran on the low side and are only listed on the unit.
8. **Differential packages.** `zarf.package.differential` (info) records the base version and the components left out. Image completeness is then recorded as not assessed, with the reason, because the images are in the base. Whether that base is on the high side cannot be known offline.
9. **Everything inside** goes through the ordinary archive walk:
   * component tars: charts, manifests, host files, git repositories;
   * image layers (gzip tars): **models in images** reach the model handlers;
   * `sboms.tar` and `documentation.tar`.
10. **Unit.** `zarf-package` holds:
    * members: the package, its definition, checksums, signature, component tars, image index, SBOMs and documentation;
    * name, version, kind, architecture, schema and the Zarf version that built it;
    * the checksum summary and the signature outcome;
    * per-component images, charts, manifests, repositories, data injections and file counts;
    * host files, action counts, `onCreate` commands, and the differential base.

    Zarf's own SBOMs are recorded as present. They are the builder's claim; superscrubber104's SBOM is built from what it inspected.

**Not built:** split packages (`.partNNN`), packages pulled from OCI registries, running anything Zarf would run, and checking a package against a live cluster.

### Validation

Tests are in `tests/test_zarf.py`. The packages in `tests/zarf_fixtures.py` are synthetic, built to the §35.2 layout and signed with throwaway keys, a throwaway Fulcio-like CA and a throwaway log. They cover:
* clean, v1beta1 and unknown-schema packages;
* a changed member, `checksums.txt`, component file or `zarf.yaml`;
* an unlisted file; a listed file or an image that is absent;
* differential packages;
* host actions and files;
* key and keyless signatures, an unaccepted identity, a re-signing key and a stripped signature;
* a model inside an image layer;
* zstd when it can be read, and not assessed when it cannot.

Damaged and odd packages are in `tests/test_vendor_robustness.py`.

The real `zarf-init-amd64-v1.0.1.tar.zst` (§35.2) was inspected again, from the scratchpad, with Python 3.14 and Sigstore's public trusted root pinned for `zarf.package`. Accepted identity: `https://github.com/zarf-dev/zarf/.github/workflows/release.yml@refs/tags/v*`, issuer `https://token.actions.githubusercontent.com`. It took 28 seconds for 411 MB and 11,846 artifacts.

| Check | Result |
|---|---|
| Keyless signature | verified offline |
| Aggregate checksum and `checksums.txt` | 35 of 35 files match |
| Component files with a recorded checksum | 3 of 3 match |
| Images named by components | 4 of 4 in the image index |
| Host actions | 11 `onDeploy`/`onRemove` commands, k3s's `systemctl` and clean-up commands among them |
| Host files | 4, including `/usr/sbin/k3s` and its symlinks |
| Trust | 36 members at signature level |
| Contents walked | charts, manifests, the k3s airgap image archive (zstd), image layers |
| Depth limit | not reached at 5 |

With an identity the policy does not accept, the signature is `untrusted` (not `invalid`), and the 36 members fall back to checksum level.

## 35.6 Hauler hauls (as built, cheap part only)

`handlers/hauler.py`, kind `hauler.haul`, unit `hauler-haul`.

**Recognised** by Hauler's default name (`haul*.tar`, `haul*.tar.gz`, `haul*.tar.zst`), with a tar, gzip or zstd header. It is treated as a haul only if `oci-layout` and `index.json` are at its root. A haul under another name is read as an OCI image archive when it is a plain tar, with every image check; compressed, nothing reads its layout, so its layout and signature rules are recorded as not assessed with the name to give it. Cosign signatures and attestations in any OCI layout (a haul, an image archive, a Zarf package's images) are recorded as not assessed, never as verified. A correctly named haul is not also read as a `docker save` archive by the container handler.

**One streaming pass**, decompressed through `archive.capped` within the archive limits: `maxRatio` (judged above `ratioMinBytes`) and `maxExpandedBytes`, the same rule as the archive walk. A package that would expand further is not assessed, hashes every member and keeps the small JSON documents (`containers.MemoryStore`). Then:

* **Layout.** The container checks run over the whole layout:
  * every blob hashes to its name, and every referenced blob is present;
  * a blob that differs is `container.layer.digest-mismatch`, and one that is missing is `container.image.incomplete`, both existing rules; the mismatch is final;
  * images get the usual image checks.
* **What each entry is.** Each manifest is classified from its media types and Hauler's `kind` annotation as an image, a Helm chart, a file (named from its layer's `org.opencontainers.image.title`), a signature, an attestation or an SBOM. Only images get image checks, so a chart or a signature is never reported as "runs as root". Content decides before labels: a manifest with an image config and any filesystem layer is an image, whatever its `kind` annotation or tag (`.sig`, `.att`) says, because nothing authenticates those. Labels only name manifests whose layers are all signatures, attestations, SBOMs, charts or files. This change is in the container handler and applies to any OCI layout (doc 20).
* **Signatures.** When a haul carries cosign signatures or attestations, `upstream.signature.invalid` and `.untrusted` are recorded as **not assessed**. The reason says that superscrubber104 does not verify cosign signatures yet, and that Hauler verifies them when it saves and loads. The unit says `signaturesVerified: false`.
* **Contents.** The archive walk inspects every blob:
  * image layers, so models in images reach the model handlers;
  * chart archives;
  * files.
* **Units.** `hauler-haul` lists images, charts, files, signatures, attestations, SBOMs and anything unrecognised. The images also form a `container-image` unit rooted at the haul.

No new rules were needed.

**Validation.** `tests/test_hauler.py` covers a synthetic haul (`tests/hauler_fixtures.py`) holding:
* an image with a model in its layer;
* a chart;
* a file;
* a cosign signature.

It is checked as tar, gzip and, on 3.14, zstd; changed and missing blobs are also tested. Damaged and odd hauls are in the robustness tests. **Not validated on a real haul**: none was published to examine, and the owner chose not to build one with Hauler (§35.7, question 5). The layout follows Hauler's documentation and source constants. Check one real haul before relying on the classification of charts, files and signatures.

**Not built:**
* verifying cosign signatures, which are simple-signing payloads in OCI artifacts, a different format from Sigstore bundles;
* chunked hauls (`haul.tar.zst.001`, …), which are walked as unrecognised files;
* hauls under names other than Hauler's default.

## 35.7 Review decisions

The owner's answers to the questions this document raised:

1. **Unlisted files in a Zarf package** are final, signed or not: content nobody vouched for.
2. **Actions** are medium (require approval) always, whoever signed the package.
3. **zstd before Python 3.14** stays not assessed, with advice. Revised after review: the optional `zstd` extra (`pip install 'superscrubber104[zstd]'`, the `backports.zstd` package) reads it, as an optional extra; the core still has no dependency for it. The real `zarf-init-amd64-v1.0.1.tar.zst` reads the same on 3.12 with the extra as on 3.14 (35 of 35 checksums, the image complete).
4. **Archive depth:** the default `maxDepth` is 5 globally.
5. **More real samples:** no Zarf or Hauler binary is run to build them. v1beta1, key-signed, differential and split packages are covered by synthetic fixtures only, built from the published Go types. A published sample of each should be checked when one is found.
6. **Scope:** Zarf first, Hauler after.

## 35.8 Sources

Checked 16 November 2026.

* Zarf 1.0 announcement, OpenSSF: <https://openssf.org/blog/2026/11/09/announcing-zarf-1-0-security-and-stability-for-airgap-software-delivery/>
* Zarf releases (v1.0.0, v1.0.1 notes and assets): <https://github.com/zarf-dev/zarf/releases>
* Zarf package reference: <https://docs.zarf.dev/ref/packages/>
* Zarf package signing: <https://docs.zarf.dev/ref/package-signing/>
* Zarf SBOMs: <https://docs.zarf.dev/ref/sboms/>
* Zarf vulnerability scanning with Grype: <https://docs.zarf.dev/best-practices/vulnerability-scanning/>
* Zarf differential packages: <https://docs.zarf.dev/tutorials/9-package-create-differential/>
* Zarf Go types: `src/api/v1alpha1/package.go` at v1.0.1, <https://raw.githubusercontent.com/zarf-dev/zarf/v1.0.1/src/api/v1alpha1/package.go>; v1beta1, <https://pkg.go.dev/github.com/zarf-dev/zarf/src/api/v1beta1>
* Zarf v1.0 summary (secondary; used only for points the primary sources also state): <https://byteiota.com/zarf-1-0-air-gapped-kubernetes-delivery-goes-stable/>
* LeapfrogAI: <https://github.com/defenseunicorns/leapfrogai>
* Hauler documentation: <https://docs.hauler.dev/docs/intro>
* Hauler `store save` reference: <https://rancherfederal.github.io/hauler-docs/docs/guides-references/command-line/hauler-store>
* Hauler releases (v2.1.0 to v2.1.2 notes): <https://github.com/hauler-dev/hauler/releases>
* Hauler constants: <https://raw.githubusercontent.com/hauler-dev/hauler/main/pkg/consts/consts.go>
* Hauler 2.1 announcement: <https://ranchergovernment.com/blog/hauler-2-1-faster-artifact-retrieval-better-visibility-more-control>
* Sigstore public trusted root (used to verify the real package): <https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json>
