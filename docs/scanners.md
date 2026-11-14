# Scanners: ClamAV, Trivy and the CISA KEV feed

airlock works without any external scanner. Its own checks cover integrity, model formats, packages, agents, secrets and active content. Two questions need a scanner and a database that changes every day:

| Question | Plugin | What airlock records without it |
|---|---|---|
| Is there known malware in the delivery? | **ClamAV** (`clamscan`) | `malware.detected`: *not assessed* |
| Do the packages and images have known vulnerabilities? | **Trivy** | `vuln.component.known`: *not assessed* |
| Which of those vulnerabilities are being exploited? | **CISA KEV** catalogue (a data file) | vulnerability findings carry `kev=unknown` |

"Not assessed" is a recorded gap, never a silent pass. By default it is a warning. A site that requires scanning makes it a blocker in the policy:

```yaml
rules:
  - rule: "malware.*"
    disposition: block
    notAssessed: block      # a delivery that was not scanned does not pass
```

This guide covers getting each tool, checking that it is genuine, carrying it to the disconnected side, and configuring airlock to use it.

## How airlock treats a scanner

Scanners cross the gap like everything else, and airlock does not trust them either. Before it lets a scanner see any content, airlock:

1. finds the binary at the path the policy gives. Nothing is picked up from `PATH` unless the policy leaves out `path`.
2. hashes the binary and every pinned database file, and compares them with `binarySha256` and `files`. A mismatch is `plugin.integrity.mismatch`. It is **final**, like a bundle hash mismatch: the scanner does not run, and no approval overrides it.
3. refuses a signature or database file in the scanner's directory that the policy does not pin. A planted allow-list file would otherwise be loaded silently.
4. reads the version (`--version`) and compares it with `minVersion`.
5. reads the database's age from the database itself and compares it with `maxDbAge` (`plugin.data.stale`).

When a scanner runs, it gets an argument list (never a shell), no standard input, a private working directory, and a cleaned environment. Its proxy variables point at a closed local port, so a scanner that tries to reach the network fails at once. The host should have no route out anyway.

Every assessment records each plugin's version, binary hash, database version and age, and whether it was pinned. The evidence states which scanner build and database produced each result.

`airlock plugins check --policy policy.yaml` runs steps 1 to 5 and reports the result without scanning anything. Run it after every installation or update.

## ClamAV

### Get it (connected side)

| Platform | Source |
|---|---|
| Ubuntu / Debian | `apt install clamav` (provides `clamscan` and `freshclam`) |
| AlmaLinux / RHEL | `dnf install epel-release && dnf install clamav clamav-update` |
| Windows | the installer or portable zip from <https://www.clamav.net/downloads> |
| Any | the official `clamav/clamav` container image |

Verify the download as the publisher describes: distribution packages through the distribution's signed repositories, and release archives from clamav.net through their published GPG signatures. Use a release that has been out for a while; do not take a release on the day it appears.

### Get the signatures (connected side)

ClamAV's databases are `main.cvd`, `daily.cvd` (or `daily.cld`) and `bytecode.cvd`. For an air gap, Cisco's `cvdupdate` tool is the documented way to fetch whole database files for an offline mirror:

```sh
python -m pip install cvdupdate
cvd config set --dbdir ./clamav-db
cvd update
```

`freshclam --datadir ./clamav-db` also works. Either way you end up with a directory of `.cvd` / `.cld` files.

ClamAV checks each CVD's digital signature from Cisco Talos when it loads it. That is the upstream layer of trust. airlock adds the transit layer (your pins and your bundle signature).

**Your own rules.** ClamAV loads YARA rules (`.yar`, `.yara`) and its own signature formats (`.hdb`, `.ndb`, `.ldb`, ...) from the same directory. Put site rules there and pin them like the CVDs.

### Configure

```yaml
plugins:
  clamav:
    required: true
    path: tools/clamav/clamscan          # clamscan.exe on Windows; relative to the policy file
    database: tools/clamav/db            # always given: airlock never uses the host's own
    binarySha256: "…"
    files:
      main.cvd: "…"
      daily.cvd: "…"
      bytecode.cvd: "…"
    minVersion: "1.4"
    maxDbAge: 7d
```

airlock runs, once per delivery:

```
clamscan --database=<database> --no-summary --stdout --max-filesize=4000M --max-scansize=4000M
         --alert-exceeds-max=yes --file-list=<list of top-level files> [args...]
```

ClamAV looks inside archives itself. A file or archive that exceeds ClamAV's own limits (`Heuristics.Limits.Exceeded.*`) is recorded as *not assessed*, not as clean. Files over 4000 MiB, which ClamAV cannot scan, are recorded the same way. In practice these are large model shards, which airlock's own format parsers check for structure and embedded code.

## Trivy

### Get it (connected side)

Download the release archive for your platform from <https://github.com/aquasecurity/trivy/releases>. Each release publishes a checksums file and a Sigstore bundle for it. Verify the bundle with `cosign verify-blob`, using the certificate identity that Trivy's documentation gives for its release workflow. Then check the archive against the checksums file. As with any scanner, prefer a release that has been out for a while, and pin it: scanners and their release pipelines are attractive targets in their own right.

### Get the vulnerability database (connected side)

Trivy's air-gapped mode reads its database from a cache directory and never downloads it:

```sh
trivy image --download-db-only --cache-dir ./trivy-cache
trivy image --download-java-db-only --cache-dir ./trivy-cache   # only if you scan Java
```

The result is `trivy-cache/db/trivy.db` and `trivy-cache/db/metadata.json`, plus `trivy-cache/java-db/` if you fetched the Java database. airlock reads the database's age from `metadata.json` (`UpdatedAt`).

### Configure

```yaml
plugins:
  trivy:
    required: true
    path: tools/trivy/trivy               # trivy.exe on Windows
    database: tools/trivy/cache           # the --cache-dir above
    binarySha256: "…"
    files:
      db/trivy.db: "…"
      db/metadata.json: "…"
    minVersion: "0.60"
    maxDbAge: 7d
    timeout: 1h
```

What airlock asks Trivy to scan, so that every finding lands on the file that carries the package:

| Content | Command |
|---|---|
| Each container image (`docker save` or OCI archive, OCI layout directory) | `trivy image --input <image>` |
| Each root filesystem that is a directory of the delivery (has `etc/os-release`) | `trivy rootfs <directory>` |
| Every other package airlock identified (wheels, sdists, installed Python and npm packages, npm tarballs, ...) | `trivy sbom <CycloneDX file airlock writes>` |

Each command also gets `--cache-dir <database> --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json --quiet`. Packages appear in the SBOM only when they are in the delivery. A lockfile entry with no distribution beside it is reported as unresolvable instead (it would need the network on the high side).

Severity comes from Trivy's data (`CRITICAL` to `LOW`; `UNKNOWN` is treated as medium). Each finding has the attributes `id`, `severity`, `package`, `ecosystem`, `fixed` (`true` when a fixed version exists) and `kev`. A policy can select on any of these:

```yaml
rules:
  - rule: vuln.component.known          # rules match first to last
    where: { kev: "true" }
    disposition: block
  - rule: vuln.component.known
    where: { fixed: "false" }
    disposition: require-approval
```

## CISA Known Exploited Vulnerabilities

The KEV catalogue is a JSON file published by CISA at <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>. It is data, not a program: airlock reads it and marks each vulnerability finding `kev=true` or `kev=false` (matching CVE aliases too). Its age is taken from its `dateReleased`.

```yaml
plugins:
  kev:
    path: feeds/known_exploited_vulnerabilities.json
    files: { known_exploited_vulnerabilities.json: "…" }   # relative to the file's directory
    maxDbAge: 2d
```

## Carrying the scanners across

Scanners and their databases are content like any other, so move them with airlock:

1. On the connected side, put the binaries, the ClamAV signature directory, the Trivy cache and the KEV file in one directory, and `airlock pack` it as its own bundle. Its signature and the receiving ledger then record exactly which scanner kit crossed, and when.
2. On the disconnected side, `airlock verify` the bundle and install its contents where the policy points.
3. Update the pins in the policy (`airlock plugins check` prints the binary hash; use `sha256sum` or `Get-FileHash` for the database files) and roll the policy out through your normal change process. Policy changes are logged as `policy.digest.changed`.
4. Run `airlock plugins check --policy policy.yaml`. It should report every plugin as `ready`.

The very first scanner kit is a bootstrap case: verify it by hand, using the publisher's signatures as above, before you trust it to verify anything else.

Databases change daily and binaries change monthly. Choose `maxDbAge` to match how often you can transfer: a scan against a 30-day-old database misses everything published since. A stale database still runs; `plugin.data.stale` records its age, and the policy decides what that means.

## Check the integration

After configuring, check that each scanner actually reports:

- **ClamAV:** add a site signature for a harmless file to the database directory (an `.hdb` line is `md5:size:name`), pin it, and inspect a directory containing that file. You should get one `malware.detected` finding with your signature's name. Avoid the EICAR test file on workstations: endpoint protection will usually quarantine it before airlock sees it.
- **Trivy:** inspect a deliberately old image or wheel (for example a release of a popular library with a published CVE) and check that `vuln.component.known` findings appear on that file.

```sh
airlock plugins check --policy policy.yaml
airlock model inspect ./test-delivery --policy policy.yaml
```
