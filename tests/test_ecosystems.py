"""Java, Go, Rust and .NET: lockfiles resolved against the delivery, hashes, sidecar checksums and
build hooks. Packages are built here; the readers were also checked against real files (a Go
module from proxy.golang.org against sum.golang.org, a crate against the crates.io index, a nupkg
against nuget.org's catalog hash, a Maven Central jar against its .sha1)."""

import base64
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from airlock.core.model import Result, TrustLevel, Verdict
from airlock.formats.golang import hash1, mod_hash, zip_hash
from airlock.handlers.packages.nuget import normalize_version
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import write


def _zip(files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data)
    return out.getvalue()


def _tgz(files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unit(result, kind: str):  # type: ignore[no-untyped-def]
    [unit] = [u for u in result.analysis.units if u.kind.value == kind]
    return unit


def _failing(result, rule: str) -> list[str]:  # type: ignore[no-untyped-def]
    return sorted(
        f.subject.display for f in findings_of(result).get(rule, []) if f.result is Result.FAIL
    )


# --- Go -----------------------------------------------------------------------------------------


def test_go_hash1_is_dirhash() -> None:
    files = {"m@v1.0.0/go.mod": b"module m\n", "m@v1.0.0/a.go": b"package m\n"}
    lines = "".join(f"{_sha256(files[n])}  {n}\n" for n in sorted(files))
    expected = "h1:" + base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()
    assert zip_hash(io.BytesIO(_zip(files))) == expected
    assert hash1([(n, _sha256(d)) for n, d in files.items()]) == expected
    assert mod_hash(b"module m\n") == hash1([("go.mod", _sha256(b"module m\n"))])


def _module(path: str, version: str, body: bytes = b"package m\n") -> tuple[bytes, bytes]:
    mod = f"module {path}\n".encode()
    return _zip({f"{path}@{version}/go.mod": mod, f"{path}@{version}/m.go": body}), mod


def test_go_sum_against_module_cache(tmp_path: Path) -> None:
    good_zip, good_mod = _module("example.com/Good", "v1.0.0")
    bad_zip, _ = _module("example.com/bad", "v1.2.0")
    tampered, _ = _module("example.com/bad", "v1.2.0", b"package m // changed\n")
    go_sum = "\n".join(
        [
            f"example.com/Good v1.0.0 {zip_hash(io.BytesIO(good_zip))}",
            f"example.com/Good v1.0.0/go.mod {mod_hash(good_mod)}",
            f"example.com/bad v1.2.0 {zip_hash(io.BytesIO(bad_zip))}",
            "example.com/absent v0.1.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ]
    )
    cache = "gopath/pkg/mod/cache/download"
    files: dict[str, bytes | str] = {
        "app/go.sum": go_sum,
        f"{cache}/example.com/!good/@v/v1.0.0.zip": good_zip,
        f"{cache}/example.com/!good/@v/v1.0.0.mod": good_mod,
        f"{cache}/example.com/!good/@v/v1.0.0.ziphash": "h1:not-the-hash=",
        f"{cache}/example.com/bad/@v/v1.2.0.zip": tampered,
    }
    result = inspect(write(tmp_path / "d", files))
    unit = _unit(result, "go-environment")
    assert (unit.attributes["requirements"], unit.attributes["hashChecked"]) == (4, 2)
    assert unit.attributes["unresolvable"] == ["example.com/absent@v0.1.0"]
    assert _failing(result, "environment.lock.hash-mismatch") == [
        f"{cache}/example.com/bad/@v/v1.2.0.zip"
    ]
    assert _failing(result, "package.checksum-mismatch") == [
        f"{cache}/example.com/!good/@v/v1.0.0.zip"
    ]
    purls = {c.purl for c in result.analysis.components}
    assert "pkg:golang/example.com/Good@v1.0.0" in purls
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_go_vendor_mode(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "app/go.sum": "example.com/dep v1.0.0 h1:x=\nexample.com/other v2.0.0 h1:y=\n",
        "app/vendor/modules.txt": "# example.com/dep v1.0.0\n## explicit\nexample.com/dep\n"
        "# example.com/local v0.0.0 => ./local\n",
        "app/vendor/example.com/dep/dep.go": "package dep\n",
    }
    result = inspect(write(tmp_path / "d", files))
    unit = _unit(result, "go-environment")
    assert (unit.attributes["requirements"], unit.attributes["vendored"]) == (1, 1)
    assert "environment.lock.unresolvable" not in findings_of(result)


# --- Rust ---------------------------------------------------------------------------------------


def _crate(name: str, version: str, *, build: bool = False) -> bytes:
    root = f"{name}-{version}"
    files: dict[str, bytes] = {
        f"{root}/Cargo.toml": f'[package]\nname = "{name}"\nversion = "{version}"\n'
        'license = "MIT OR Apache-2.0"\n'.encode(),
        f"{root}/src/lib.rs": b"pub fn f() {}\n",
    }
    if build:
        files[f"{root}/build.rs"] = b"fn main() {}\n"
    return _tgz(files)


def test_cargo_lock_crates_and_vendored(tmp_path: Path) -> None:
    good, built = _crate("good", "1.0.0"), _crate("built", "0.2.0", build=True)
    lock = "\n".join(
        [
            "version = 3",
            "[[package]]",
            'name = "app"',
            'version = "0.1.0"',
            "[[package]]",
            'name = "good"',
            'version = "1.0.0"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            f'checksum = "{_sha256(good)}"',
            "[[package]]",
            'name = "built"',
            'version = "0.2.0"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            f'checksum = "{_sha256(b"the published crate")}"',
            "[[package]]",
            'name = "vend"',
            'version = "3.0.0"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            f'checksum = "{"ab" * 32}"',
            "[[package]]",
            'name = "gone"',
            'version = "9.9.9"',
            'source = "git+https://git.example.org/gone#abc"',
        ]
    )
    lib = b"pub fn v() {}\n"
    checksum = {
        "files": {"src/lib.rs": _sha256(b"original"), "build.rs": _sha256(b"x")},
        "package": "ab" * 32,
    }
    files: dict[str, bytes | str] = {
        "app/Cargo.lock": lock,
        "registry/good-1.0.0.crate": good,
        "registry/built-0.2.0.crate": built,
        "app/vendor/vend/Cargo.toml": '[package]\nname = "vend"\nversion = "3.0.0"\n',
        "app/vendor/vend/src/lib.rs": lib,
        "app/vendor/vend/.cargo-checksum.json": json.dumps(checksum),
    }
    result = inspect(write(tmp_path / "d", files))
    unit = _unit(result, "rust-environment")
    assert unit.attributes["requirements"] == 4  # the path package "app" is not a download
    assert unit.attributes["unresolvable"] == ["gone@9.9.9"]
    assert _failing(result, "environment.lock.hash-mismatch") == ["registry/built-0.2.0.crate"]
    [vendored] = findings_of(result)["package.checksum-mismatch"]
    assert (vendored.detail["modified"], vendored.detail["missing"]) == (
        ["src/lib.rs"],
        ["build.rs"],
    )
    hooks = {
        f.subject.display: f.detail["hooks"] for f in findings_of(result)["package.build-hooks"]
    }
    assert hooks == {
        "registry/built-0.2.0.crate": ["build-script"],
        "app/vendor/vend/.cargo-checksum.json": ["build-script"],
    }
    [good_part] = [c for c in result.analysis.components if c.purl == "pkg:cargo/good@1.0.0"]
    assert good_part.licenses[0].expression == "MIT OR Apache-2.0"


# --- .NET ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normal"),
    [
        ("1.0", "1.0.0"),
        ("01.02.03", "1.2.3"),
        ("1.2.3.0", "1.2.3"),
        ("1.2.3.4", "1.2.3.4"),
        ("2.0.0-beta.1+sha", "2.0.0-beta.1"),
    ],
)
def test_nuget_version_normalisation(raw: str, normal: str) -> None:
    assert normalize_version(raw) == normal


def _nupkg(package_id: str, version: str, *, hooks: bool = False) -> bytes:
    nuspec = (
        '<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
        f"<metadata><id>{package_id}</id><version>{version}</version><authors>Example</authors>"
        '<license type="expression">MIT</license></metadata></package>'
    )
    files = {f"{package_id}.nuspec": nuspec.encode(), "lib/net8.0/x.dll": b"MZ"}
    if hooks:
        files["build/x.targets"] = b"<Project/>"
        files["tools/install.ps1"] = b"Write-Host hi"
    return _zip(files)


def test_nuget_lockfile_packages_and_sidecar(tmp_path: Path) -> None:
    good = _nupkg("Example.Good", "1.0")
    hooked = _nupkg("Example.Hooked", "2.1.0", hooks=True)

    def content_hash(data: bytes) -> str:
        return base64.b64encode(hashlib.sha512(data).digest()).decode()

    lock = {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "Example.Good": {
                    "type": "Direct",
                    "resolved": "1.0.0",
                    "contentHash": content_hash(good),
                },
                "Example.Hooked": {
                    "type": "Transitive",
                    "resolved": "2.1.0",
                    "contentHash": content_hash(b"other"),
                },
                "Example.Missing": {
                    "type": "Transitive",
                    "resolved": "3.0.0",
                    "contentHash": content_hash(b"m"),
                },
                "MyLib": {"type": "Project"},
            }
        },
    }
    files: dict[str, bytes | str] = {
        "src/packages.lock.json": json.dumps(lock),
        "feed/example.good/1.0.0/example.good.1.0.0.nupkg": good,
        "feed/example.good/1.0.0/example.good.1.0.0.nupkg.sha512": content_hash(b"tampered"),
        "feed/example.hooked.2.1.0.nupkg": hooked,
    }
    result = inspect(write(tmp_path / "d", files))
    unit = _unit(result, "dotnet-environment")
    assert (unit.attributes["requirements"], unit.attributes["hashChecked"]) == (3, 1)
    assert unit.attributes["unresolvable"] == ["example.missing@3.0.0"]
    assert _failing(result, "environment.lock.hash-mismatch") == ["feed/example.hooked.2.1.0.nupkg"]
    assert _failing(result, "package.checksum-mismatch") == [
        "feed/example.good/1.0.0/example.good.1.0.0.nupkg"
    ]
    [hooks] = findings_of(result)["package.build-hooks"]
    assert hooks.detail["hooks"] == ["msbuild", "powershell"]
    [part] = [c for c in result.analysis.components if c.name == "Example.Good"]
    assert (part.purl, part.licenses[0].expression) == ("pkg:nuget/Example.Good@1.0.0", "MIT")


# --- Java ---------------------------------------------------------------------------------------


def _jar(group: str, name: str, version: str) -> bytes:
    props = f"groupId={group}\nartifactId={name}\nversion={version}\n".encode()
    return _zip(
        {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
            f"META-INF/maven/{group}/{name}/pom.properties": props,
        }
    )


def test_maven_and_gradle(tmp_path: Path) -> None:
    lib = _jar("org.example", "lib", "1.0.0")
    util = _jar("org.example", "util", "2.0.0")
    other = _jar("org.example", "other", "3.0.0")
    pom = b"<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0.0</version></project>"
    verification = (
        '<?xml version="1.0"?><verification-metadata xmlns="https://schema.gradle.org/dependency-verification">'
        "<components>"
        '<component group="org.example" name="lib" version="1.0.0">'
        f'<artifact name="lib-1.0.0.jar"><sha256 value="{_sha256(lib)}"/></artifact>'
        f'<artifact name="lib-1.0.0.pom"><sha256 value="{_sha256(pom)}"/></artifact></component>'
        '<component group="org.example" name="util" version="2.0.0">'
        f'<artifact name="util-2.0.0.jar"><sha256 value="{_sha256(b"published util")}"/></artifact></component>'
        "</components></verification-metadata>"
    )
    m2 = "m2/repository/org/example"
    gradle = "gradle-home/caches/modules-2/files-2.1/org.example"
    files: dict[str, bytes | str] = {
        "app/gradle.lockfile": "org.example:lib:1.0.0=runtimeClasspath\norg.example:util:2.0.0=runtimeClasspath\n"
        "org.example:absent:9.0=runtimeClasspath\nempty=\n",
        "app/gradle/verification-metadata.xml": verification,
        f"{m2}/lib/1.0.0/lib-1.0.0.jar": lib,
        f"{m2}/lib/1.0.0/lib-1.0.0.jar.sha1": hashlib.sha1(lib).hexdigest(),  # noqa: S324
        f"{m2}/lib/1.0.0/lib-1.0.0.pom": pom,
        f"{m2}/lib/1.0.0/lib-1.0.0.pom.sha256": _sha256(b"not the pom"),
        f"{gradle}/util/2.0.0/{hashlib.sha1(util).hexdigest()}/util-2.0.0.jar": util,  # noqa: S324
        f"{gradle}/other/3.0.0/{'0' * 40}/other-3.0.0.jar": other,
    }
    result = inspect(write(tmp_path / "d", files))
    units = {
        u.attributes["lockfile"]: u.attributes
        for u in result.analysis.units
        if u.kind.value == "jvm-environment"
    }
    assert units["gradle.lockfile"]["unresolvable"] == ["org.example:absent@9.0"]
    assert units["verification-metadata.xml"]["hashChecked"] == 2
    assert _failing(result, "environment.lock.hash-mismatch") == [
        f"{gradle}/util/2.0.0/{hashlib.sha1(util).hexdigest()}/util-2.0.0.jar"  # noqa: S324
    ]
    assert _failing(result, "package.checksum-mismatch") == [
        f"{gradle}/other/3.0.0/{'0' * 40}/other-3.0.0.jar",
        f"{m2}/lib/1.0.0/lib-1.0.0.pom",
    ]
    [check] = artifact(result, f"{m2}/lib/1.0.0/lib-1.0.0.jar").verifications
    assert (check.type, check.level) == ("maven-checksum", TrustLevel.CHECKSUM)
    assert "pkg:maven/org.example/lib@1.0.0" in {c.purl for c in result.analysis.components}
