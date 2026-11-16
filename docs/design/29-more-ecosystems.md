# 29. Java, Go, Rust and .NET

> **Status: implemented.** Spec: [§4](04-artifact-coverage.md) (software, language environments), [§3](03-core-concepts.md) (units). Python and npm, which came first, are in [20](20-software-and-agents.md).

For a build or restore on the high side to work, everything the lockfile pins has to be in the delivery, and it has to be exactly what was pinned. Each ecosystem handler reads its lockfiles and its packages. One shared assembler, `airlock/units/locked_env.py`, then decides resolvability and hashes in the same way for all four.

## 29.1 The shared model

Handlers make two kinds of claim:

* **`lockfile`**: requirements `{name, version, hashes, vendored}`. Hashes are `"<algorithm>:<value>"`, in hex for sha256/sha512/sha1 and as-is for Go's `h1:`. The unit root is the lockfile itself: a Gradle project has both `gradle.lockfile` and `verification-metadata.xml`, and each is its own unit.
* **`distribution`**: something in the delivery that satisfies a requirement, `{name, version, hashes, bomRef}`.

A requirement is resolved by a distribution with the same name and version. When both record a hash with the same algorithm, one must match. A mismatch is `environment.lock.hash-mismatch`, final: the lockfile travelled with the content, and the build tool would refuse it too. A requirement nothing satisfies is `environment.lock.unresolvable`. A requirement with a hash that nothing can be compared with is counted as `hashUnverifiable`. Units: `jvm-environment`, `go-environment`, `rust-environment`, `dotnet-environment`.

Two cross-cutting rules:

* **`package.checksum-mismatch`** (final): a package differs from a checksum its own tooling recorded beside it: NuGet's `.nupkg.sha512`, Go's `.ziphash`, a Gradle cache directory named after the file's sha1, or cargo's `.cargo-checksum.json`. Sidecar checksums published with an artifact (Maven's `.sha1`/`.sha256`/`.sha512`/`.md5`) are publishers' checksum lists and are checked for any file by the upstream handler ([27.5](27-vendor-trust.md)): a mismatch there is `upstream.checksum-mismatch`, and a match gives a `checksum`-level verification.
* **`package.build-hooks`** (info): code that runs at build or install time, recorded for review. This covers Cargo build scripts and procedural macros, MSBuild `.targets`/`.props` under `build/`, and NuGet PowerShell scripts.

Lockfiles and packages inside archives are read the same way, so a source tree delivered as a zip still forms its units. Everything a handler decompresses itself is read through a cap (`archive.capped`): a module zip up to Go's own 500 MiB limit, a crate up to 512 MiB expanded, a provider package up to 4 GiB. A package that cannot be read satisfies no requirement, so its lockfile reports it as unresolvable.

## 29.2 Go

| Input | What is read |
|---|---|
| `go.sum` | every `module version h1:` (the module zip) and `module version/go.mod h1:` line |
| `vendor/modules.txt` next to it | the vendored modules; with it, these are the requirements and they count as resolved (`-mod=vendor`), and go.sum's other lines are not needed |
| `.../cache/download/<module>/@v/<version>.zip`, `.mod`, `.ziphash` | a module cache (`GOMODCACHE`, or a file-based `GOPROXY`); `!x` path escapes are undone |

`h1:` is Go's dirhash: the sha256 of the lines `"<sha256>  <name>\n"` for each file in the module zip, sorted by name, in base64. It is computed from the zip as the go command does (`formats/golang.py`). It was checked against `sum.golang.org` for a real module, for both the zip and the `go.mod` hash. Components: `pkg:golang/<module>@<version>`.

Without vendoring, go.sum can list more modules than one build needs, so `unresolvable` is conservative. Run `go mod download` on the low side before packing.

## 29.3 Rust

* **`Cargo.lock`** (v1 to v4): registry and git packages are requirements. Registry packages carry the sha256 of the `.crate` (`checksum`, or `[metadata]` in v1). Path packages are local source and are skipped.
* **`.crate`** files (a local registry or a directory of downloads) are hashed. Their `Cargo.toml` is read for `build` and `lib.proc-macro`, and a top-level `build.rs` is noted.
* **`cargo vendor` directories**: `.cargo-checksum.json` records every file's sha256 and the original crate's. Modified or missing files are `package.checksum-mismatch`, since cargo itself would refuse them. The recorded crate hash is matched against `Cargo.lock`.

Checked against `itoa 1.0.11` (its `.crate` sha256 equals the crates.io index `cksum`) and `serde_derive 1.0.200` (reported as a procedural macro). Components: `pkg:cargo/<name>@<version>`, with the licence from the manifest.

## 29.4 .NET

* **`packages.lock.json`**: each package per target framework with `resolved` and `contentHash`, the base64 sha512 of the `.nupkg`. `Project` entries are skipped. Names are case-insensitive. Versions are normalised as NuGet does (`1.0` → `1.0.0`, a zero fourth part dropped, build metadata removed).
* **`.nupkg`**: identity, authors and licence come from the `.nuspec` (the licence only when it is declared as an SPDX expression, not when it names a file). Build hooks are listed, and a `.nupkg.sha512` beside the package (the global packages folder) is checked. Whether the package carries a repository or author signature (`.signature.p7s`) is recorded, **not verified**: that needs CMS with the NuGet certificate chain and timestamping (see limits).

Checked against `Newtonsoft.Json 13.0.3`: the computed content hash equals `packageHash` in nuget.org's catalog. Components: `pkg:nuget/<id>@<version>`.

## 29.5 Java

* **Jars, wars, aars and poms**: identity comes from the jar's single `META-INF/maven/**/pom.properties`, the pom (with its parent for the group and version), the Gradle cache layout, or, for a jar without `pom.properties` in a Maven layout, the `.pom` beside it. A shaded jar carries the `pom.properties` of everything merged into it, so no identity is read from those. A jar signature (`META-INF/*.SF`) is recorded, not verified. Detached `.asc` signatures from Maven Central are verified by the upstream handler ([27.5](27-vendor-trust.md)) against keys pinned for `file.signed`.
* **Maven repository layout**: sidecar checksums are checked by the upstream handler, like those of any other file.
* **Gradle cache** (`files-2.1/<group>/<artifact>/<version>/<sha1>/<file>`): the directory name is the file's sha1 and is checked.
* **`gradle.lockfile`**: versions only. **`gradle/verification-metadata.xml`**: versions and hashes per artifact file. Requirements name components (`group:artifact`) or files (`group:artifact:file`), and each jar or pom claims both.

Checked against `commons-io 2.16.1` from Maven Central: the jar and pom match their `.sha1` files. Components: `pkg:maven/<group>/<artifact>@<version>`.

## 29.6 Limits

* `pom.xml` dependency lists are not resolved. Without a lockfile, versions come from parents, BOMs, properties and ranges, which needs a Maven resolver. Use Gradle locking or verification metadata, or ship a resolved repository with checksums.
* NuGet package signatures and jar signatures are recorded, not verified. Both are CMS/PKCS#7 with vendor certificate chains and timestamps. That verification belongs with Authenticode in `airlock patch` (Windows), where the same machinery is needed.
* `go.work`, `replace` directives pointing outside the delivery, and Cargo `[patch]` sections are not interpreted.
* Conda, Ruby gems, PHP Composer and Swift are not covered yet. Their files are still inventoried, hashed and scanned as unclassified or generic archives.
