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

AlmaLinux 8 and older keep the RPM database in Berkeley DB, which airlock does not read. `patch inventory` says so and names the command to run on the host instead; its output is passed with `--package-list` (also usable on any host, when running the package manager is preferred to reading its database):

```sh
rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\n' > packages.txt        # RPM hosts
dpkg-query -W -f='${Package} ${Version} ${Architecture} ${source:Package}\n' > packages.txt  # Debian, Ubuntu
airlock patch inventory --root / --package-list packages.txt --label old-01 --key keys/receipt.key -o old-01.inventory.json
```

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

Every feed reports when it was built: the newest `modified`, `issued` or `updated` date, `CurrentReleaseDate` or `dateReleased`. `freshness.feeds` in the policy sets the maximum age by feed kind (`osv`, `updateinfo`, `msrc`, `kev`), with `default` as the fallback. A feed older than that, or unreadable, is stale: the plan says so and `patch plan` exits 1 (the plan is still written). A stale feed silently misses advisories, which is exactly the failure a patch process must not have.

## 33.3 Plan and confirm

```sh
airlock patch plan --inventory web-01.inventory.json --feed updateinfo.xml.gz --feed kev.json \
    --policy policy.yaml -o plan.json --markdown plan.md
airlock patch plan ... --kev                      # emergency: only advisories with a KEV CVE
airlock patch plan ... --cve CVE-2026-1111        # emergency: only this CVE
airlock patch confirm --plan plan.json --inventory web-01.after.json --feed ... # exit 1 while gaps remain
```

* **Matching.** A fix applies when its ecosystem names the host's distribution and release (major version for AlmaLinux and Rocky Linux, exact for Ubuntu). Fixes without one, such as updateinfo, apply as given. An installed package older than the fix, by `rpm` or `dpkg` ordering ([27.3](27-vendor-trust.md), [27.4](27-vendor-trust.md)), is a gap. Architecture-specific fixes only match that architecture (or `noarch`). Ubuntu fixes name source packages and are matched through each installed binary's `Source`.
* **Windows.** A KB is missing when it is neither installed nor superseded, transitively, by an installed KB. A missing KB that a newer missing KB supersedes is dropped, so the plan asks for the newest update only.
* **Ubuntu Pro.** Canonical publishes some fixes only to Ubuntu Pro (ESM) subscribers. When a fix exists in the standard archive, that one is planned. A fix that exists only for Pro is still listed, marked `ubuntu-pro` (and "(Ubuntu Pro)" in the Markdown), so that nobody plans around a package the site cannot fetch. Subscription credentials never enter a plan or an inventory.
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
| `authenticode.signature.untrusted` | policy | the tool reports the verification failed for any other reason: an issuer that chains to no pinned root, an expired certificate without a timestamp |
| `authenticode.signature.missing` | policy | no signature |

Only an explicit digest mismatch is final: there the tool says the content is not what was signed. Output with no verdict at all (a crash, an unsupported file) is recorded as not assessed, never guessed at.

Without the plugin these are not assessed whenever the delivery holds Windows packages. Setup: [docs/scanners.md](../scanners.md).

## 33.5 Validation and tests

The readers were checked against real snapshots:

* AlmaLinux 9 BaseOS `updateinfo.xml` (529 security errata);
* `USN-7064-1` and `ALSA-2024:9180` from osv.dev;
* the November 2024 MSRC CVRF (35 KBs with supersedence);
* the CISA KEV catalogue (1,781 CVEs).

A synthetic AlmaLinux 9.4 host against the real errata produced 128 gaps, 13 of them KEV. A Windows Server 2022 host was correctly missing the month's cumulative updates. `tests/test_patch.py` covers:

* inventories (RPM, dpkg, a package listing, the Berkeley DB refusal, Windows, signing, tampering, the label rule);
* each feed reader;
* RPM, Rocky, Ubuntu (including Pro-only fixes) and Windows plans, emergency filters, stale and unreadable feeds, the Markdown output and confirmation;
* the CLI end to end with a pinned receipt key;
* the Authenticode plugin: signed, altered, signed under another root, unsigned, no verdict, and not configured.

## 33.6 Limits

* Dependency closure is resolved on the connected side by the package manager, not by airlock.
* The plan does not compare the bundle's packages with the inventory. Downgrade protection happens at staging ([34](34-staging.md)).
* Ubuntu OVAL and Red Hat CSAF/VEX are not read; OSV covers the same advisories.
* Windows: only the KB model (cumulative updates and supersedence within the documents given). Feature updates, Office click-to-run and driver updates are not planned, and WSUS metadata is not read.
* Authenticode results are findings only. They do not feed `trust.minimumLevels`, because scanners run after the analysis.
* The `osslsigncode` and `qemu-img` plugins are tested with stand-ins for the binaries, as every scanner is. Their handling of each tool's real output has **not** been run against the real tools here: check `airlock plugins check` and one known-good and one altered file on your own build before relying on them.
* Feeds are read as given. `patch plan` does not verify where a feed came from: check its publisher's checksum or signature as for any download, or take `updateinfo.xml` from a mirror whose chain `airlock verify` has checked ([28](28-package-mirrors.md)).
* GPU driver, CUDA and firmware versions are in the inventory, but no advisory feed is matched against them yet.
* Two versions of the same package in one bundle are both staged; the older one is not flagged as superseded.
