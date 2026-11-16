# 35. Zarf and Hauler

> **Status: research done; the handler is a proposal awaiting review. Nothing in §35.4 to §35.7 is implemented.** Facts below are from the projects' own documentation, release notes and source code, and from one real Zarf package examined offline (§35.2). Sources are in §35.8. Where a source was secondary or a fact could not be confirmed, that is said.

Zarf and Rancher Government Hauler are open-source tools for moving content into disconnected environments. They overlap with airlock's transport side. Their job is to move content and deploy it. airlock's job is to inspect content, decide by policy whether it may cross, and record evidence of why. This document records what they do as of November 2026, so that airlock can work with them rather than duplicate them, and proposes how airlock should inspect their packages.

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

What was checked, using airlock's existing primitives in a throwaway script:

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

Both tools overlap with airlock, and in places do more than it does:

* **Integrity and signing.** Zarf's checksum chain and Hauler's per-artifact cosign checks overlap with airlock's bundle signature. Zarf's offline keyless verification is close to what airlock does for model signatures.
* **Splitting and deltas.** Zarf split packages and differential packages, and Hauler's chunked hauls, overlap with airlock's multi-volume and delta bundles.
* **Delivery.** Both deploy or serve content; `airlock stage` only writes files and indexes.
* **SBOM and scanning.** Zarf generates SBOMs, and Grype on them gives a vulnerability gate, much as airlock's Trivy plugin does.

What airlock adds, which neither documents:

* **Inspection of what is inside.** Model formats read without loading them, pickle opcodes, `trust_remote_code`, chat templates, embedding-model consistency, injected instructions in corpora and agent configuration, secrets, active content in documents, offline readiness.
* **An independent decision on the receiving side.** Re-hashing and re-inspecting with the receiving side's own policy and keys. Integrity rules that nothing can override. Approval quorums with written justifications. A replay ledger.
* **Evidence for an assessment.** Every check mapped to NIST SP 800-53 / ITSG-33 controls, rendered as OSCAL and CycloneDX, with checks that could not run recorded as not assessed.
* **Content beyond Kubernetes.** VM images, OS patch planning, IDE extensions, bare-metal GPU stacks. (Zarf also places host files and runs host actions; its centre is still a Kubernetes cluster.)

They are complementary: Zarf or Hauler builds and moves the package, and airlock inspects it before it is allowed to cross and again on arrival. The useful work for airlock is to read their packages as well as it reads anything else.

## 35.5 Proposal: inspecting a Zarf package

### Two prerequisites in the core

1. **zstd.** Zarf packages are zstd-compressed by default, and airlock's archive walker recognises zstd but cannot open it, so today a Zarf package is hashed and recorded with its contents **not assessed**. Python 3.14's standard library reads zstd (`compression.zstd`), with no new dependency. Proposal: on 3.14 and later, zstd joins gzip, bzip2 and xz in the walker, with the same expansion budget. Before 3.14 it stays not assessed, with the advice to build with `metadata.uncompressed: true` or to decompress before packing. Zarf's checksums cover the members, not the compressed archive, so a decompressed package remains fully verifiable.
2. **Images in an OCI layout inside an archive.** The container handler finds an OCI layout through `resolve()`, which does not reach into archives, so the images in `images/` would not be checked. Proposal: factor the container handler's layout checks (index to manifests to configs and layers, each digest equal to its name, every referenced blob present) so that they run over a store built from a streaming pass, as well as over a directory. The Zarf handler then supplies that store.

### The handler (`handlers/zarf.py`, kind `zarf.package`)

Recognised by name (`zarf-package-*.tar[.zst]`, `zarf-init-*.tar[.zst]`), confirmed by finding `zarf.yaml` in the archive. **One streaming pass** over the archive:

* hashes every member with sha256;
* keeps only the small control files: `zarf.yaml`, `checksums.txt`, `zarf.bundle.sig`, `images/index.json`, and image manifests and configs (blobs under 4 MiB);
* holds nothing else in memory, so a 400 MiB package costs one read.

Then, in order:

1. **Definition.** `zarf.yaml` is read with the untrusted YAML loader. The schema is taken from `apiVersion` (none or `zarf.dev/v1alpha1`, or `zarf.dev/v1beta1`; anything else is recorded as not assessed). The field locations that differ between the two are handled explicitly.
2. **Checksum chain** (records that travelled with the content, so mismatches are final):
   * the sha256 of `checksums.txt` against `aggregateChecksum`;
   * each listed file against `checksums.txt`;
   * a listed file that is absent.
   A file present but neither listed nor named in `build.provenanceFiles` is not covered by the publisher's checksums or signature (see question 1).
3. **Signature.** `zarf.bundle.sig` is verified against keys pinned in `trust.upstream` with a new scope, `zarf.package`:
   * keyless: `type: sigstore`, with the trusted root and accepted identities and issuers, exactly as for model signatures;
   * key or KMS: `type: x509` with the public key in PEM.
   This needs `formats/sigstore.py` to accept a message-signature bundle with a `hashedrekord` log entry as well as the DSSE bundles of model signing. The scratch check in §35.2 shows that the pieces are already there.
   * The outcome reuses `upstream.signature.invalid` (final) and `upstream.signature.untrusted`.
   * A package whose `zarf.yaml` says `signed: true` but carries no signature file is recorded as untrusted with that reason. (Stripping the signature and editing the flag would leave no trace; a site that needs signed packages says so with `trust.minimumLevels`.)
4. **Trust levels.** A verified signature gives `zarf.yaml` a signature-level verification. Through the checksum chain, every member gets one too, as dnf and apt mirrors do (doc 28). An unsigned but consistent package gives its members checksum level.
5. **Images.** The layout checks run over the `images/` store (prerequisite 2). Every image `zarf.yaml` names must be in `images/index.json`, after reference normalisation, unless the package is differential (see 9).
6. **Component files.** Each `files` entry with a recorded `shasum` or `checksum` is compared with the file in the component tar: final on mismatch.
   * A file whose target is a host path (anything not under `###ZARF_TEMP###` or the cluster) is listed on the unit with its target and whether it is executable.
   * Downloaded files with no recorded checksum are noted.
7. **Actions.** `onDeploy` and `onRemove` commands run on the deploying host with the deployer's rights. They are reported, with the command text and component, as `zarf.component.actions`, as maintainer scripts and agent hooks are. `onCreate` actions ran on the low side and are only listed.
8. **Everything inside.** The rest needs no new code once zstd is readable: the analyzer's archive walk already descends into the members.
   * Component tars hold charts (templates recorded as not rendered, doc 30), manifests (workload posture, doc 30), host files (the executables handler) and git repositories (source).
   * Image layer blobs are gzip tars, walked like any other, so **models inside images** (the usual way LeapfrogAI-style packages carry them) meet the model handlers.
   * `sboms.tar` and `documentation.tar` are walked as archives.
   * The nesting is deeper than usual (package, layer, files), so `limits.archive.maxDepth` may need to rise from 4 to 5 for Zarf packages (see question 4).
9. **Differential packages.** `build.differential`, the reference version and the components left out are recorded. Image completeness is then not assessed, with the reason. Whether the base is present on the high side cannot be known offline; the unit says which base it needs.
10. **Unit.** A new unit kind, `zarf-package`, holds:
    * members: definition, signature, checksums, components, images;
    * name, version, kind (init or package), architecture and schema;
    * signature status, signer identity and anchor;
    * per-component images, charts, manifests, host files and actions;
    * the differential base.
    The SBOMs Zarf made are recorded as present; they are the packer's claim, and airlock's own SBOM is built from what it inspected.

Proposed rules (the integrity class is decided per the conventions in CLAUDE.md):

| Rule | Severity | Class | When |
|---|---|---|---|
| `zarf.package.checksum-mismatch` | critical | final | aggregate checksum, a listed file, or a component file's recorded checksum does not match |
| `zarf.package.incomplete` | critical | final | a file `checksums.txt` lists is absent, or an image `zarf.yaml` names is not in the image index (non-differential) |
| `zarf.package.unlisted` | high | see question 1 | a file the checksums and provenance list do not cover |
| `zarf.component.actions` | medium | policy | commands that run on the deploying host |
| `zarf.component.host-files` | low | policy | files written to host paths, especially executables |
| `zarf.package.differential` | info | policy | the package needs a base version on the high side |
| `upstream.signature.invalid` / `.untrusted` | existing | existing | the signature, reused with scope `zarf.package` |

**Not proposed now:**

* split packages (`.partNNN`): their metadata format has not been seen;
* packages pulled from OCI registries;
* running anything Zarf would run;
* checking packages against a live cluster.

### Tests and validation

* Synthetic packages are built in `tests/zarf_fixtures.py` to the layout in §35.2: uncompressed tar on any Python, zstd on 3.14. They are signed with throwaway keys and a throwaway Fulcio-like CA and log key, as the model-signing tests already do.
* Cases: a clean package; a changed member, `checksums.txt` or `zarf.yaml`; a stripped signature; an unpinned signer; a missing image; a host action; a differential package; a model inside an image layer.
* Damaged samples join `tests/test_vendor_robustness.py`.
* The real init package is checked again from the scratchpad before the work is committed, and the result recorded here. A v1beta1 package and a key-signed package should be found or built for the same check (see question 5).

## 35.6 Proposal: Hauler hauls (cheap part only)

With zstd readable, a haul is an OCI layout in a tar, and prerequisite 2 already reads that:

* image digests are checked (existing final rule `container.layer.digest-mismatch`);
* charts (Helm chart layers, `.tgz`) and files (Hauler file layers) are walked as content;
* the `kind` annotations identify what each entry is.

A small `hauler.haul` kind would add a unit listing images, charts, files, and which artifacts carry signatures, attestations and SBOMs.

**Not cheap, so deferred:** verifying the cosign image signatures a haul carries. They are a different format from Sigstore bundles (simple-signing payloads in OCI artifacts). Hauler itself verifies them before saving and after loading, so for now airlock would record their presence, not their validity.

## 35.7 Questions for review

1. **Unlisted files in a Zarf package.** Final, as `integrity.entry.unexpected` is for airlock's own bundles? A file the publisher's signature does not cover is content nobody vouched for. Or high and policy? Recommendation: final when the package is signed, high when it is not.
2. **Actions severity.** Medium (require approval) for any `onDeploy` or `onRemove` command, or info when the package's signature verified against a pinned publisher? Recommendation: medium always. The commands run as root on hosts, and approval is cheap evidence.
3. **zstd before Python 3.14.** Accept "not assessed" with advice on 3.11 to 3.13? Or allow an optional `zstandard` dependency? Recommendation: stdlib only, as the dependency rule in CLAUDE.md asks.
4. **Archive depth.** Raise the default `maxDepth` from 4 to 5 globally, or only within a recognised Zarf package?
5. **More real samples.** May a pinned Zarf binary be run in the scratchpad, never in the repository or tests, to build a v1beta1, a key-signed, a differential and a split package for validation? The alternative is to find published ones. The same question applies to Hauler, where building one sample haul would confirm §35.3.
6. **Scope.** Zarf first, Hauler after (as above)? Or both in one change?

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
