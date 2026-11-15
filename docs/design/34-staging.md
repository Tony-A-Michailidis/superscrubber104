# 34. Staging

> **Status: implemented.** Spec: [§14](12-transfer-workflow-and-cli.md) step 6 (stage), [§16](12-transfer-workflow-and-cli.md) (`airlock stage`), [§11](11-os-patching.md) (patch staging, downgrade protection). Patch planning: [33](33-patching-and-feeds.md).

```sh
airlock verify bundle/ --policy policy.yaml --state /var/lib/airlock --key keys/receipt.key
airlock stage bundle/ --policy policy.yaml --state /var/lib/airlock --key keys/receipt.key \
    --target pypi=/srv/pypi --target models=/srv/models --target dnf=/srv/repos
airlock patch stage bundle/ --inventory web-01.inventory.json --policy policy.yaml \
    --state /var/lib/airlock --key keys/receipt.key --target dnf=/srv/repos
```

## 34.1 Only what was accepted, exactly as it was verified

1. `stage` verifies the bundle again with this side's policy and keys, **without** touching the ledger. The units it stages therefore come from this side's own analysis, never from the packer's. Multi-volume and delta bundles work as in verify (`--volume`, `--base`).
2. The ledger must hold an **accepted receipt for exactly this manifest**, so `airlock verify --state` must have run first. The fresh verdict must still be `passed`: a policy change or a newly expired waiver since acceptance stops staging.
3. Every file is **re-hashed while it is copied**, to a `.airlock-partial` file, and compared with the manifest. It is fsynced and moved into place only if it matches, so a file changed between verification and staging never lands. Destinations are resolved and must stay inside the target directory.
4. Existing files are **never overwritten**. An identical file counts as already present; a different one is an error. Staging the same bundle twice is safe.
5. A `stage` event goes into the ledger, signed with the receipt key (required when the policy pins one). It records the bundle, the manifest digest, the digest of the stage report and per-target counts.

`verify()` gained a `use` callback for this. It receives the trusted manifest, the re-derived analysis and assessment, and every payload file as re-hashed, while they are still on disk: split files of a multi-volume bundle exist only for the duration of the call.

## 34.2 Targets

airlock writes files and indexes. It never pushes to a registry or calls a service, because there is no network at runtime. Where the receiving tool must finish the job, the report says how.

| Target | What is staged | Layout | Next step printed |
|---|---|---|---|
| `files` | every payload file | the bundle's paths | |
| `models` | every model-package unit | `<model>/<paths below the unit root>` | |
| `pypi` | wheels and sdists | PEP 503: `packages/` plus `simple/<project>/index.html` with `#sha256=` links, regenerated from everything in `packages/` | `pip install --no-index --find-links …`, or serve `simple/` |
| `npm` | npm tarballs | Verdaccio storage: `<name>/<name>-<version>.tgz` plus a packument with `shasum` and `integrity`, merged with existing versions | point Verdaccio's storage here |
| `dnf` | dnf mirror units **as they came**, so vendor `repomd.xml` and its signature are kept; loose RPMs | `<mirror>/…`, `local/Packages/` | `createrepo_c --update`, then sign with the site key |
| `apt` | apt mirror units as they came (`InRelease` kept); loose debs | `<mirror>/…`, `local/pool/` | build the index with reprepro or aptly, signed with the site key |
| `oci` | container-image units | `<image>/…` (the archive or OCI layout) | `skopeo copy … docker://<registry>/<image>` |
| `windows` | `.msu`, `.cab`, `.msi`, `.exe`, `.msix`, `.appx` | flat | import into WSUS, or deploy from the share |

The stage report (`StageReport`) lists, per target, files copied and already present, the items staged and the notes. Its digest is in the ledger.

## 34.3 Patch staging and downgrade protection

`airlock patch stage` is `stage` with one more check, made after verification and before anything is copied. Every RPM or Debian package in the bundle is compared with the host's inventory ([33.1](33-patching-and-feeds.md)). A package older than the installed one would roll a fix back, so staging is refused and the downgrades are listed. With `--allow-downgrade "<justification>"` it proceeds, and the justification and the downgrades are kept in the stage report, whose digest is in the ledger.

## 34.4 Tests and limits

`tests/test_stage.py` packs a mixed delivery and verifies it with a ledger. It then:

* stages every target and checks the layouts, the ledger event and that a second stage is idempotent;
* refuses an unaccepted bundle, an unknown target and an unsigned event;
* changes a file between verification and copy (caught, and nothing lands);
* refuses to overwrite;
* covers downgrade protection (allowed, refused, justified);
* runs the CLI.

Not done:

* direct publication to registries, Pulp, Artifactory or WSUS (by design, see above);
* repodata generation for loose RPMs and debs (`createrepo_c`, reprepro);
* a Hugging Face cache layout for models (the `models` target keeps the delivered layout).
