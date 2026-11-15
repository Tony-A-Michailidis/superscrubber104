# 33. Patching disconnected hosts, and security feeds

> **Status: implemented** (inventory, feeds, plan, confirm, Authenticode). Spec: [§11](11-os-patching.md) (OS updates and critical patches). Staging into local repositories: [34](34-staging.md). Mirrors and their freshness and rollback checks: [28](28-package-mirrors.md).

```
high side                          low side                               high side
airlock patch inventory  ──────▶   airlock patch plan  ──▶ fetch, pack ──▶ verify, stage
  (signed, names+versions)            (feeds: OSV, updateinfo,                  │
                                       CVRF, KEV)                               ▼
                                                                 airlock patch inventory
                                                                 airlock patch confirm
```

## 33.1 Inventory (high side)

```sh
airlock patch inventory --root / --label web-01 --key keys/receipt.key -o web-01.inventory.json
airlock patch inventory --windows-hotfixes hotfix.json --windows-product "Windows Server 2022" \
    --windows-build 10.0.20348.2700 --label dc-01 --key keys/receipt.key -o dc-01.inventory.json
```

Linux hosts are read statically from a root filesystem: `etc/os-release`, the RPM database (`var/lib/rpm/rpmdb.sqlite` or `usr/lib/sysimage/rpm/rpmdb.sqlite`, opened read-only and immutable) or dpkg's `status`. The NVIDIA driver version (`/sys/module/nvidia/version`) and CUDA's `version.json` are added when present. Nothing is executed, so the same command inventories a mounted image or an exported container filesystem.

Windows hosts are read from what PowerShell reports, because airlock runs on Linux:

```powershell
Get-HotFix | Select-Object HotFixID | ConvertTo-Json > hotfix.json
(Get-CimInstance Win32_OperatingSystem).Version          # the build for --windows-build
```

**The inventory is the only thing that crosses high to low, so its schema is the leak boundary.** It holds:

* the OS family, ID, version and name;
* package names, versions and architectures, and Debian source package names;
* KB numbers;
* the GPU driver and CUDA versions.

It holds no host name: the operator gives a label of letters, digits, dots, dashes and underscores. It also holds no paths, users or configuration. It is a DSSE envelope signed with the high side's receipt key. `patch plan` and `patch confirm` refuse an inventory that the low side's policy does not pin a receipt key for (when the policy pins any).

## 33.2 Feeds (low side)

Offline snapshots, read by `airlock/feeds/readers.py` into one advisory model (`Advisory`, `Fix`):

| Feed | Format | Gives |
|---|---|---|
| OSV | one JSON record, a directory or a zip of them (`osv.dev` exports, `canonical/ubuntu-security-notices/osv`, `AlmaLinux/osv-database`) | per ecosystem (`AlmaLinux:9`, `Ubuntu:24.04:LTS`, `Ubuntu:Pro:…`) the fixed version. For Ubuntu the source package and its binaries |
| dnf `updateinfo.xml[.gz/.xz]` | the errata a dnf repository carries, reached through its signed `repomd.xml` ([28](28-package-mirrors.md)) | security advisories, fixed EVR per arch, CVEs, severity, issue dates |
| Microsoft CVRF | the MSRC monthly document in JSON (`api.msrc.microsoft.com/cvrf/v3.0/cvrf/<yyyy-Mmm>` with `Accept: application/json`) | per KB: products, CVEs, severity, restart required, supersedence |
| CISA KEV | `known_exploited_vulnerabilities.json` | the CVEs known to be exploited |

Every feed reports when it was built: the newest `modified`, `issued` or `updated` date, `CurrentReleaseDate` or `dateReleased`. `freshness.feeds` in the policy sets the maximum age by feed kind (`osv`, `updateinfo`, `msrc`, `kev`), with `default` as the fallback. A feed older than that, or unreadable, is stale: the plan says so and `patch plan` exits 3. A stale feed silently misses advisories, which is exactly the failure a patch process must not have.

## 33.3 Plan and confirm

```sh
airlock patch plan --inventory web-01.inventory.json --feed updateinfo.xml.gz --feed kev.json \
    --policy policy.yaml -o plan.json --markdown plan.md
airlock patch plan ... --kev                      # emergency: only advisories with a KEV CVE
airlock patch plan ... --cve CVE-2026-1111        # emergency: only this CVE
airlock patch confirm --plan plan.json --inventory web-01.after.json --feed ... # exit 2 while gaps remain
```

* **Matching.** A fix applies when its ecosystem names the host's distribution and release (major version for AlmaLinux, exact for Ubuntu). Fixes without one, such as updateinfo, apply as given. An installed package older than the fix, by `rpm` or `dpkg` ordering ([27.3](27-vendor-trust.md), [27.4](27-vendor-trust.md)), is a gap. Architecture-specific fixes only match that architecture (or `noarch`). Ubuntu fixes name source packages and are matched through each installed binary's `Source`.
* **Windows.** A KB is missing when it is neither installed nor superseded, transitively, by an installed KB. A missing KB that a newer missing KB supersedes is dropped, so the plan asks for the newest update only.
* **Each gap** carries the advisory, severity, CVEs, KEV status, whether it needs a reboot, the age of the advisory in days, and the package versions. Reboot is decided from the packages actually updated: kernel, glibc, systemd, firmware, microcode, `openssl-libs` and the other packages `dnf needs-restarting -r` treats that way, or the vendor's flag. AlmaLinux does not publish `reboot_suggested`.
* **Order**: KEV first, then by severity.
* **Fetch list**: the newest fixed version of each package, in the form the package manager takes (`name-version-release.arch` for `dnf download`, `name=version` for `apt-get download`, KB numbers). Resolve dependencies on the connected side (`dnf download --resolve`, `apt-get install --download-only`), pack, and verify as usual.
* **Confirm** re-plans against a fresh inventory and lists the plan's advisories as closed or still open, plus any new ones. That is the flaw-remediation evidence for SI-2.

The plan (`PatchPlan`) is a JSON document. `--markdown` writes the human summary, with the gap table, feed freshness and fetch list.

## 33.4 Authenticode on Linux

The `osslsigncode` plugin verifies Authenticode signatures on top-level Windows updates and binaries (`.msu`, `.cab`, `.msi`, `.exe`, `.dll`, `.sys`, `.msix`, `.appx`, and any PE). It checks them against the root certificates pinned under `plugins.osslsigncode.database` (`roots.pem`, optionally `tsa-roots.pem`), never the host's trust store.

| Rule | Class | When |
|---|---|---|
| `authenticode.signature.invalid` | final | the content does not match its signature (digest mismatch) |
| `authenticode.signature.untrusted` | policy | the signature holds but does not chain to a pinned root |
| `authenticode.signature.missing` | policy | no signature |

Without the plugin these are not assessed whenever the delivery holds Windows packages. Setup: [docs/scanners.md](../scanners.md).

## 33.5 Validation and tests

The readers were checked against real snapshots:

* AlmaLinux 9 BaseOS `updateinfo.xml` (529 security errata);
* `USN-7064-1` and `ALSA-2024:9180` from osv.dev;
* the November 2024 MSRC CVRF (35 KBs with supersedence);
* the CISA KEV catalogue (1,781 CVEs).

A synthetic AlmaLinux 9.4 host against the real errata produced 128 gaps, 13 of them KEV. A Windows Server 2022 host was correctly missing the month's cumulative updates. `tests/test_patch.py` covers:

* inventories (RPM, dpkg, Windows, signing, tampering, the label rule);
* each feed reader;
* RPM, Ubuntu and Windows plans, emergency filters, staleness, the Markdown output and confirmation;
* the CLI end to end with a pinned receipt key;
* the Authenticode plugin, configured and not.

## 33.6 Limits

* Dependency closure is resolved on the connected side by the package manager, not by airlock.
* The plan does not compare the bundle's packages with the inventory. Downgrade protection happens at staging ([34](34-staging.md)).
* Ubuntu OVAL and Red Hat CSAF/VEX are not read; OSV covers the same advisories.
* Windows: only the KB model (cumulative updates and supersedence within the documents given). Feature updates, Office click-to-run and driver updates are not planned, and WSUS metadata is not read.
* Authenticode results are findings only. They do not feed `trust.minimumLevels`, because scanners run after the analysis.
