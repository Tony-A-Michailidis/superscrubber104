"""npm packages, lockfiles, offline resolvability, and source recognition."""

import json
from collections.abc import Mapping
from pathlib import Path

from airlock.core.model import Severity, UnitKind, Verdict
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import npm_tarball, package_lock, sri, write

LEFTPAD = npm_tarball("left-pad", "1.3.0")
EVIL = npm_tarball("evil-helper", "0.0.1", scripts={"postinstall": "node collect.js"})


def _env(result, root: str):  # type: ignore[no-untyped-def]
    return next(
        u
        for u in result.analysis.units
        if u.kind is UnitKind.NODE_ENVIRONMENT and u.root.display == root
    )


def project(
    root: Path,
    lock: Mapping[str, Mapping[str, object]],
    files: Mapping[str, bytes | str] | None = None,
) -> Path:
    contents: dict[str, bytes | str] = {
        "app/package.json": json.dumps(
            {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}}
        ),
        "app/package-lock.json": package_lock(lock),
    }
    contents.update(files or {})
    return write(root, contents)


def test_installed_node_modules_resolve(tmp_path: Path) -> None:
    lock = {
        "node_modules/left-pad": {
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": sri(LEFTPAD),
        }
    }
    installed = {"app/node_modules/left-pad/package.json": json.dumps({"name": "left-pad", "version": "1.3.0", "license": "MIT"}),
                 "app/node_modules/left-pad/lib/package.json": json.dumps({"type": "module"})}  # fmt: skip
    result = inspect(project(tmp_path / "d", lock, installed), licences=True)
    assert findings_of(result) == {}
    env = _env(result, "app")
    assert env.name == "app"
    assert env.attributes["installed"] == 1  # the nested lib/package.json is not a package
    assert env.attributes["unresolvable"] == []


def test_offline_mirror_of_tarballs(tmp_path: Path) -> None:
    lock: dict[str, dict[str, object]] = {
        "node_modules/left-pad": {"version": "1.3.0", "integrity": sri(LEFTPAD)},
        "node_modules/fsevents": {
            "version": "2.3.3",
            "integrity": "sha512-" + "A" * 86 + "==",
            "optional": True,
        },
        "node_modules/absent": {"version": "9.9.9", "integrity": "sha512-" + "B" * 86 + "=="},
    }
    result = inspect(project(tmp_path / "d", lock, {"mirror/left-pad-1.3.0.tgz": LEFTPAD}))
    found = findings_of(result)
    unresolvable = {f.detail["kind"]: f for f in found["node.environment.unresolvable"]}
    assert [m["name"] for m in unresolvable["required"].detail["missing"]] == ["absent"]
    assert unresolvable["optional"].severity is Severity.LOW
    env = _env(result, "app")
    assert any(
        m.role == "tarball" and m.artifact.path == "mirror/left-pad-1.3.0.tgz" for m in env.members
    )


def test_tarball_that_does_not_match_the_lockfile(tmp_path: Path) -> None:
    lock = {"node_modules/left-pad": {"version": "1.3.0", "integrity": sri(LEFTPAD)}}
    swapped = npm_tarball("left-pad", "1.3.0", scripts={"install": "node steal.js"})
    result = inspect(project(tmp_path / "d", lock, {"mirror/left-pad-1.3.0.tgz": swapped}))
    found = findings_of(result)
    [mismatch] = found["node.environment.integrity-mismatch"]
    assert mismatch.subject.display == "mirror/left-pad-1.3.0.tgz"
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert found["npm.package.install-script"][0].detail["scripts"] == {"install": "node steal.js"}


def test_install_scripts(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "app/package.json": json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "scripts": {"postinstall": "node setup.js", "test": "jest"},
            }
        ),
        "app/node_modules/evil/package.json": json.dumps(
            {"name": "evil", "version": "1.0.0", "scripts": {"preinstall": "node prepare.js"}}
        ),
        "app/node_modules/native/package.json": json.dumps({"name": "native", "version": "1.0.0"}),
        "app/node_modules/native/binding.gyp": "{}",
        "vendor/evil-helper-0.0.1.tgz": EVIL,
    }
    found = findings_of(inspect(write(tmp_path / "d", files)))
    scripts = {f.subject.display: f for f in found["npm.package.install-script"]}
    assert scripts["app/package.json"].severity is Severity.LOW  # the project's own script
    assert scripts["app/node_modules/evil/package.json"].severity is Severity.MEDIUM
    assert (
        "node-gyp" in scripts["app/node_modules/native/package.json"].detail["scripts"]["install"]
    )
    assert scripts["vendor/evil-helper-0.0.1.tgz"].detail["scripts"] == {
        "postinstall": "node collect.js"
    }


def test_yarn_and_pnpm_lockfiles(tmp_path: Path) -> None:
    yarn = (
        '# yarn lockfile v1\n\n"left-pad@^1.3.0":\n  version "1.3.0"\n'
        f'  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc"\n  integrity {sri(LEFTPAD)}\n\n'
        '"private-lib@git+https://git.example.org/team/private-lib.git":\n  version "0.1.0"\n'
        '  resolved "git+https://git.example.org/team/private-lib.git#0123abc"\n'
    )
    pnpm = (
        "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n"
        f"    resolution: {{integrity: {sri(LEFTPAD)}}}\n"
    )
    result = inspect(
        write(
            tmp_path / "d",
            {"y/yarn.lock": yarn, "p/pnpm-lock.yaml": pnpm, "mirror/left-pad-1.3.0.tgz": LEFTPAD},
        )
    )
    found = findings_of(result)
    [remote] = found["node.lockfile.remote-source"]
    assert remote.detail["packages"][0]["package"] == "private-lib"
    assert _env(result, "p").attributes["unresolvable"] == []
    assert _env(result, "y").attributes["unresolvable"] == ["private-lib@0.1.0"]


def test_npm_allowlist(tmp_path: Path) -> None:
    lock = {"node_modules/left-pad": {"version": "1.3.0", "integrity": sri(LEFTPAD)},
            "node_modules/@scope/thing": {"version": "2.0.0", "integrity": "sha512-x"}}  # fmt: skip
    root = project(tmp_path / "d", lock, {"mirror/left-pad-1.3.0.tgz": LEFTPAD})
    allow = "allowlists:\n  npm: {mode: report, entries: ['left-pad@^1']}\n"
    [finding] = findings_of(inspect(root, policy_yaml=allow))["package.allowlist.unapproved"]
    assert finding.detail["packages"] == [{"name": "@scope/thing", "version": "2.0.0"}]
    assert finding.severity is Severity.INFO


# --- source -------------------------------------------------------------------------------------


def test_source_recognition(tmp_path: Path) -> None:
    minified = "var a=1;" * 2000
    result = inspect(
        write(
            tmp_path / "d",
            {
                "src/main.py": "def main():\n    return 1\n",
                "web/app.min.js": minified,
                "web/app.ts": "export const x: number = 1;\n",
                "repo.bundle": "# v2 git bundle\n0123abc refs/heads/main\n\nPACK....",
            },
        )
    )
    assert artifact(result, "src/main.py").kinds == ("source.python",)
    assert artifact(result, "web/app.ts").kinds == ("source.typescript",)
    assert artifact(result, "repo.bundle").metadata["gitBundle"]["refs"] == ["refs/heads/main"]
    [minified_finding] = findings_of(result)["source.minified"]
    assert minified_finding.subject.display == "web/app.min.js"
    assert minified_finding.severity is Severity.INFO
