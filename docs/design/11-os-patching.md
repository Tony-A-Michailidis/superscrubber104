# 13. OS updates and critical patches

Patching disconnected systems is recurring, and critical vulnerabilities (especially those on the CISA Known Exploited Vulnerabilities list) need a fast, auditable path. Targets: **Windows** (server and workstation), **AlmaLinux** (8/9/10), **Ubuntu** LTS. Also covers GPU drivers/CUDA and firmware updates for AI hosts.

**Workflow**
1. **Inventory (high side).** `airlock patch inventory` collects installed packages: `rpm -qa` / `dnf updateinfo` for Alma, `dpkg-query` for Ubuntu, installed KBs and OS build for Windows, plus GPU driver/CUDA versions. Output is a signed inventory that crosses *outbound* (package names and versions only; policy confirms nothing else leaks).
2. **Plan (low side).** `airlock patch plan --inventory inv.json --feeds <offline snapshots>` matches the inventory against AlmaLinux ALSA/OVAL, Ubuntu USN/OVAL, Microsoft security update data and KEV. It produces a patch gap report: missing fixes, CVEs, severity, KEV status, reboot required.
3. **Fetch and pack (low side)** with the **full dependency closure**, through the same pack/verify pipeline.
4. **Verify and stage (high side).** `airlock verify` then `airlock patch stage` into local repos: a dnf repo (regenerated `repodata/` or Pulp/Foreman), an apt repo (re-signed with the site key, or reprepro/aptly), and WSUS import or a file share. The tool stages; deployment stays with Ansible/WSUS/SCCM.
5. **Confirm.** Re-run inventory and show the gap closed. That's the flaw-remediation evidence.

**Profiles**
- **Routine:** scheduled bundles aligned to Patch Tuesday and distro security pockets.
- **Critical / emergency:** `airlock patch plan --cve CVE-XXXX-YYYY` or `--kev` produces a minimal bundle with the fix and its dependencies only. Same verification, shorter approval path, optional two-person sign-off. The report states the time from advisory publication to bundle.

**Trust and integrity rules (non-negotiable)**
- **Vendor signatures verified:** RPM GPG + signed `repomd.xml` (AlmaLinux), `InRelease`/`Release.gpg` + `Packages` hashes (Ubuntu), Authenticode with a valid Microsoft chain (Windows), vendor signatures for drivers/firmware.
- **Vendor keys are pinned inputs** in the policy and cross the airlock like any artifact. Key rotation is an explicit, logged event.
- **Downgrade and freeze protection:** reject packages older than what's installed (unless a justified rollback is approved) and repo metadata older than the last accepted snapshot or past its validity window.
- **Supersedence** flagged for Windows and within Linux bundles.
- **Subscription credentials** (Ubuntu Pro/ESM etc.) never appear in bundles or reports.

**Implementation notes:** parse `repomd.xml`/`primary.xml`/`updateinfo.xml`, `Release`/`Packages`, CVRF/CSAF data natively. Wrap `rpm`, `dpkg`, `gpgv`, `createrepo_c`, `osslsigncode` (or a Python Authenticode library) as plugins. Windows verification must run on the Linux host. Do Alma and Ubuntu first, then Windows.
