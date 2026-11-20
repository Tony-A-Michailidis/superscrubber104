"""Python packages, lockfiles and offline resolvability."""

import hashlib
import json
from pathlib import Path

import pytest

from superscrubber104.core.model import ComponentType, Severity, UnitKind, Verdict
from superscrubber104.handlers.packages.python import canon_name, canon_version, parse_wheel_name
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import wheel_bytes, wheel_name, write

WHEEL = wheel_bytes()
WHEEL_SHA = hashlib.sha256(WHEEL).hexdigest()
OTHER = wheel_bytes("otherlib", "2.0")
OTHER_SHA = hashlib.sha256(OTHER).hexdigest()


def _env(result, lockfile: str):  # type: ignore[no-untyped-def]
    return next(
        u
        for u in result.analysis.units
        if u.kind is UnitKind.PYTHON_ENVIRONMENT and u.root.display == lockfile
    )


def wheelhouse(root: Path, requirements: str, *, files: dict[str, bytes] | None = None) -> Path:
    contents: dict[str, bytes | str] = {
        f"wheels/{wheel_name()}": WHEEL,
        f"wheels/{wheel_name('otherlib', '2.0')}": OTHER,
        "app/requirements.txt": requirements,
    }
    contents.update(files or {})
    return write(root, contents)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0", "1.0.0"),
        ("v2.1", "2.1"),
        ("2.0.1", "2.0.1"),
        ("1.10", "1.10.0"),
        ("2.0rc1", "2.0rc1"),
    ],
)
def test_versions_compare_the_way_pip_does(a: str, b: str) -> None:
    assert canon_version(a) == canon_version(b)


def test_names_and_wheel_filenames() -> None:
    assert canon_name("Foo_Bar.baz") == "foo-bar-baz"
    parsed = parse_wheel_name("torch-2.4.0+cu121-cp312-cp312-linux_x86_64.whl")
    assert parsed is not None
    assert (parsed.version, parsed.python, parsed.platform) == (
        "2.4.0+cu121",
        "cp312",
        "linux_x86_64",
    )
    assert parse_wheel_name("not-a-wheel.zip") is None


def test_locked_wheelhouse_resolves_offline(tmp_path: Path) -> None:
    requirements = (
        f"tinylib==1.0 \\\n    --hash=sha256:{WHEEL_SHA}\n"
        f"otherlib==2.0.0 --hash=sha256:{OTHER_SHA}  # via tinylib\n"
    )
    result = inspect(wheelhouse(tmp_path / "d", requirements), licences=True)
    found = findings_of(result)
    assert found == {}, {k: [f.detail for f in v] for k, v in found.items()}
    env = _env(result, "app/requirements.txt")
    assert env.attributes["resolved"] == 2
    assert env.attributes["hashed"] is True
    assert {m.role for m in env.members} == {"lockfile", "distribution"}
    assert len(env.components) == 2
    wheel_components = [c for c in result.analysis.components if c.purl == "pkg:pypi/tinylib@1.0.0"]
    assert wheel_components[0].licenses[0].expression == "MIT"


def test_unresolvable_and_mismatched_requirements(tmp_path: Path) -> None:
    requirements = (
        f"tinylib==1.0.0 --hash=sha256:{'0' * 64}\n"  # present, but not the locked hash
        "missinglib==3.1.4 --hash=sha256:" + "1" * 64 + "\n"
        "winonly==1.0 ; sys_platform == 'win32' --hash=sha256:" + "2" * 64 + "\n"
    )
    result = inspect(wheelhouse(tmp_path / "d", requirements))
    found = findings_of(result)
    [mismatch] = found["python.environment.hash-mismatch"]
    assert mismatch.subject.display == f"wheels/{wheel_name()}"
    assert result.assessment.summary.verdict is Verdict.REFUSED
    unresolvable = {f.detail["kind"]: f for f in found["python.environment.unresolvable"]}
    assert [m["name"] for m in unresolvable["required"].detail["missing"]] == ["missinglib"]
    assert unresolvable["conditional"].severity is Severity.LOW
    assert unresolvable["required"].severity is Severity.HIGH


def test_requirements_hygiene(tmp_path: Path) -> None:
    requirements = (
        "--extra-index-url https://packages.example.net/simple\n"
        "tinylib>=1.0\n"
        "otherlib==2.0\n"
        "git+https://git.example.org/team/private.git@main#egg=private\n"
    )
    found = findings_of(inspect(wheelhouse(tmp_path / "d", requirements)))
    assert found["python.requirements.unpinned"][0].detail["requirements"] == ["tinylib"]
    assert found["python.requirements.unhashed"][0].detail["requirements"] == ["otherlib"]
    sources = found["python.requirements.remote-source"][0].detail["sources"]
    assert {"index": "https://packages.example.net/simple"} in sources
    assert any(s.get("source") == "url" for s in sources)


def test_wheel_integrity_and_startup_hooks(tmp_path: Path) -> None:
    write(
        tmp_path / "d",
        {
            "tampered-1.0-py3-none-any.whl": wheel_bytes("tampered", "1.0", tamper=True),
            "extra-1.0-py3-none-any.whl": wheel_bytes("extra", "1.0", extra_file=True),
            "hook-1.0-py3-none-any.whl": wheel_bytes(
                "hook", "1.0", pth="import os; os.system('id')\n"
            ),
            "plain-1.0-py3-none-any.whl": wheel_bytes("plain", "1.0", pth="/opt/plain/lib\n"),
            "source-1.0.tar.gz": b"\x1f\x8b" + bytes(32),
        },
    )
    result = inspect(tmp_path / "d")
    found = findings_of(result)
    problems = {
        f.subject.display: f.detail["problems"][0]["problem"]
        for f in found["python.wheel.record-mismatch"]
    }
    assert problems == {
        "tampered-1.0-py3-none-any.whl": "content differs from RECORD",
        "extra-1.0-py3-none-any.whl": "not listed in RECORD",
    }
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert [f.subject.display for f in found["python.package.pth-file"]] == [
        "hook-1.0-py3-none-any.whl"
    ]
    assert found["python.package.build-script"][0].subject.display == "source-1.0.tar.gz"


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (
            "uv.lock",
            f"""version = 1
[[package]]
name = "app"
version = "0.1.0"
source = {{ editable = "." }}

[[package]]
name = "tinylib"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/tinylib-1.0.0-py3-none-any.whl", hash = "sha256:{WHEEL_SHA}" }}]
""",
        ),
        (
            "poetry.lock",
            f"""[[package]]
name = "tinylib"
version = "1.0.0"
files = [{{file = "tinylib-1.0.0-py3-none-any.whl", hash = "sha256:{WHEEL_SHA}"}}]
""",
        ),
        (
            "Pipfile.lock",
            json.dumps(
                {"default": {"tinylib": {"version": "==1.0.0", "hashes": [f"sha256:{WHEEL_SHA}"]}}}
            ),
        ),
        (
            "pylock.toml",
            f"""lock-version = "1.0"
[[packages]]
name = "tinylib"
version = "1.0.0"
wheels = [{{ name = "tinylib-1.0.0-py3-none-any.whl", hashes = {{ sha256 = "{WHEEL_SHA}" }} }}]
""",
        ),
    ],
)
def test_lockfile_formats(tmp_path: Path, name: str, content: str) -> None:
    result = inspect(
        write(tmp_path / "d", {f"app/{name}": content, f"wheels/{wheel_name()}": WHEEL})
    )
    env = _env(result, f"app/{name}")
    assert env.attributes["resolved"] == 1
    assert env.attributes["unresolvable"] == []
    assert "python.environment.hash-mismatch" not in findings_of(result)


def test_wheels_for_several_platforms(tmp_path: Path) -> None:
    linux = wheel_bytes("native", "1.0")
    windows = wheel_bytes("native", "1.0", licence="Apache-2.0")
    write(
        tmp_path / "d",
        {
            "wheels/native-1.0-cp312-cp312-manylinux_2_17_x86_64.whl": linux,
            "wheels/native-1.0-cp312-cp312-win_amd64.whl": windows,
            "app/requirements.txt": "native==1.0\n",
        },
    )
    result = inspect(tmp_path / "d")
    [mixed] = findings_of(result)["python.environment.platform-mixed"]
    assert mixed.detail["platforms"] == ["linux", "windows"]


def test_installed_environment(tmp_path: Path) -> None:
    site = "venv/lib/python3.12/site-packages"
    write(
        tmp_path / "d",
        {
            "venv/pyvenv.cfg": "home = /usr/bin\nversion = 3.12.4\ninclude-system-site-packages = false\n",
            f"{site}/requests-2.32.3.dist-info/METADATA": "Name: requests\nVersion: 2.32.3\nLicense-Expression: Apache-2.0\n",
            f"{site}/requests/__init__.py": "",
            f"{site}/distutils-precedence.pth": "import os; var = 'SETUPTOOLS_USE_DISTUTILS'\n",
        },
    )
    result = inspect(tmp_path / "d", licences=True)
    env = _env(result, "venv")
    assert env.attributes["packages"] == ["requests==2.32.3"]
    assert env.attributes["virtualenv"]["version"] == "3.12.4"
    [pth] = findings_of(result)["python.package.pth-file"]
    assert pth.severity is Severity.INFO  # the standard setuptools file
    assert [c.purl for c in result.analysis.components if c.type is ComponentType.LIBRARY] == [
        "pkg:pypi/requests@2.32.3"
    ]


def test_package_allowlist(tmp_path: Path) -> None:
    requirements = (
        f"tinylib==1.0.0 --hash=sha256:{WHEEL_SHA}\notherlib==2.0 --hash=sha256:{OTHER_SHA}\n"
    )
    root = wheelhouse(tmp_path / "d", requirements)
    allow = "allowlists:\n  python: {mode: enforce, entries: ['tinylib==1.0.0', 'requests']}\n"
    [finding] = findings_of(inspect(root, policy_yaml=allow))["package.allowlist.unapproved"]
    assert finding.detail["packages"] == [{"name": "otherlib", "version": "2"}]
    assert finding.severity is Severity.HIGH
    report = allow.replace("enforce", "report")
    [finding] = findings_of(inspect(root, policy_yaml=report))["package.allowlist.unapproved"]
    assert finding.severity is Severity.INFO


def test_a_licence_family_classifier_beside_an_identifier(tmp_path: Path) -> None:
    # httpx declares BSD-3-Clause and the classifier "BSD License": nothing is unidentified.
    family = "License :: OSI Approved :: BSD License"
    files = {
        f"wheels/{wheel_name('exact', '1.0')}": wheel_bytes(
            "exact", "1.0", licence="BSD-3-Clause", classifiers=(family,)
        ),
        f"wheels/{wheel_name('vague', '1.0')}": wheel_bytes(
            "vague", "1.0", licence="MIT", classifiers=(family,)
        ),
    }
    found = findings_of(inspect(write(tmp_path / "d", files), licences=True))
    unidentified = [f.subject.display for f in found.get("licence.unidentified", [])]
    assert len(unidentified) == 1 and "vague" in unidentified[0]  # BSD beside MIT is unexplained
