"""Scanner plugins: pre-flight trust checks, ClamAV, Trivy and the KEV feed.

The real scanners are not run here. ``FakeTools`` stands in for the process runner and answers
the way clamscan and trivy do, so these tests pin down what superscrubber104 passes to each tool, how it
reads the answers, and everything that happens before a tool is allowed to run.
"""

import hashlib
import json
from collections.abc import Callable, Sequence
from datetime import timedelta
from pathlib import Path

import pytest

from superscrubber104.core.model import Result, Severity, SubjectKind, Verdict
from superscrubber104.scanners import base
from superscrubber104.scanners.base import Completed, ScanError, scrubbed_environment
from tests.helpers import NOW
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import docker_archive, wheel_bytes, wheel_name, write

Runner = Callable[[Sequence[str]], Completed]


class FakeTools:
    """Stands in for ``run_process``; records every command line."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[list[str]] = []
        self.handlers: dict[str, Runner] = {}
        monkeypatch.setattr(base, "run_process", self._run)

    def _run(
        self,
        command: Sequence[str],
        *,
        timeout: float,
        workdir: Path,
        ok: Sequence[int] = (0,),
        stdin: bytes | None = None,
    ) -> Completed:
        self.calls.append(list(command))
        tool = Path(command[0]).stem
        result = self.handlers[tool](command[1:])
        if result.returncode not in ok:
            raise ScanError(f"exit code {result.returncode}")
        return result

    def commands(self, tool: str) -> list[list[str]]:
        return [c[1:] for c in self.calls if Path(c[0]).stem == tool]


def _binary(directory: Path, name: str) -> tuple[Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.exe"
    path.write_bytes(f"pretend {name} binary".encode())
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _cvd(name: str, version: int, built: int) -> bytes:
    header = f"ClamAV-VDB:10 Nov 2026 08-00 +0000:{version}:2000000:90:{'0' * 32}:sig:talos:{built}"
    return header.ljust(512).encode() + b"\x1f\x8b rest of the database"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clamav_policy(tools: Path, *, pin: bool = True, extra: str = "") -> str:
    binary, digest = _binary(tools, "clamscan")
    db = tools / "clamav-db"
    db.mkdir(exist_ok=True)
    (db / "daily.cvd").write_bytes(_cvd("daily", 27820, int(NOW.timestamp()) - 86400))
    (db / "main.cvd").write_bytes(_cvd("main", 62, int(NOW.timestamp()) - 86400 * 300))
    pins = (
        f"    binarySha256: {digest}\n"
        f"    files: {{daily.cvd: {_sha(db / 'daily.cvd')}, main.cvd: {_sha(db / 'main.cvd')}}}\n"
        if pin
        else ""
    )
    return (
        "plugins:\n  clamav:\n"
        f"    path: {binary.as_posix()}\n    database: {db.as_posix()}\n" + pins + extra
    )


def _clamscan(found: dict[str, str]) -> Runner:
    """clamscan: one line per file in the --file-list, FOUND for names in ``found``."""

    def run(args: Sequence[str]) -> Completed:
        if args == ["--version"]:
            return Completed(0, "ClamAV 1.4.3/27820/Tue Nov 10 08:00:00 2026\n", "")
        listing = next(a.split("=", 1)[1] for a in args if a.startswith("--file-list="))
        lines, hit = [], False
        for path in Path(listing).read_text(encoding="utf-8").splitlines():
            signature = next((s for name, s in found.items() if path.endswith(name)), None)
            hit |= signature is not None
            lines.append(f"{path}: {signature} FOUND" if signature else f"{path}: OK")
        return Completed(1 if hit else 0, "\n".join(lines) + "\n", "")

    return run


# --- no scanners --------------------------------------------------------------------------------


def test_without_scanners_the_gap_is_recorded(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {"a.txt": "hello"}), plugins=True)
    found = findings_of(result)
    for rule in ("malware.detected", "vuln.component.known"):
        [gap] = found[rule]
        assert gap.result is Result.NOT_ASSESSED
        assert gap.subject.kind is SubjectKind.BUNDLE
        assert "plugins." in (gap.not_assessed_reason or "")
    assert result.assessment.plugins == ()


def test_not_assessed_scans_can_be_made_to_block(tmp_path: Path) -> None:
    policy = "rules:\n  - {rule: 'malware.*', notAssessed: block}\n"
    result = inspect(write(tmp_path / "d", {"a.txt": "x"}), policy_yaml=policy, plugins=True)
    assert result.assessment.summary.verdict is Verdict.BLOCKED


# --- ClamAV -------------------------------------------------------------------------------------


def test_clamav_detection_limits_and_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools(monkeypatch)
    tools.handlers["clamscan"] = _clamscan(
        {
            "dropper.exe": "Win.Trojan.Agent-123",
            "huge.bin": "Heuristics.Limits.Exceeded.MaxFileSize",
        }
    )
    root = write(
        tmp_path / "d",
        {"dropper.exe": b"MZ not really", "huge.bin": b"\0" * 64, "notes/readme.txt": "fine"},
    )
    result = inspect(root, policy_yaml=_clamav_policy(tmp_path / "tools"), plugins=True)
    found = findings_of(result)

    [detection] = [f for f in found["malware.detected"] if f.result is Result.FAIL]
    assert detection.subject.display == "dropper.exe"
    assert detection.attributes["signature"] == "Win.Trojan.Agent-123"
    assert detection.severity is Severity.CRITICAL
    assert detection.tool.name == "clamav" and detection.tool.version == "1.4.3"
    [limit] = [f for f in found["malware.detected"] if f.result is Result.NOT_ASSESSED]
    assert limit.subject.display == "huge.bin"
    assert result.assessment.summary.verdict is Verdict.BLOCKED

    [status] = result.assessment.plugins
    assert (status.name, status.present, status.pinned, status.version) == (
        "clamav",
        True,
        True,
        "1.4.3",
    )
    assert status.data_version == "daily 27820, main 62"
    assert status.data_age_seconds == 86400  # the newest database decides
    [scan] = [c for c in tools.commands("clamscan") if c != ["--version"]]
    assert scan[0] == f"--database={(tmp_path / 'tools' / 'clamav-db').resolve()}"
    assert "--alert-exceeds-max=yes" in scan


def test_tampered_scanner_never_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = FakeTools(monkeypatch)
    policy = _clamav_policy(tmp_path / "tools")
    (tmp_path / "tools" / "clamscan.exe").write_bytes(b"something else entirely")
    result = inspect(write(tmp_path / "d", {"a.txt": "x"}), policy_yaml=policy, plugins=True)
    found = findings_of(result)
    [mismatch] = found["plugin.integrity.mismatch"]
    assert mismatch.subject.display == "policy#plugins.clamav"
    assert result.assessment.summary.verdict is Verdict.REFUSED  # final: nothing overrides it
    assert tools.calls == []
    assert found["malware.detected"][0].result is Result.NOT_ASSESSED


def test_unpinned_signature_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools(monkeypatch)
    policy = _clamav_policy(tmp_path / "tools")
    (tmp_path / "tools" / "clamav-db" / "allow-everything.ign2").write_text("Win.Trojan.Agent-123")
    found = findings_of(
        inspect(write(tmp_path / "d", {"a": "x"}), policy_yaml=policy, plugins=True)
    )
    [mismatch] = found["plugin.integrity.mismatch"]
    assert mismatch.detail["files"][0]["file"] == "allow-everything.ign2"
    assert tools.calls == []


def test_unpinned_stale_old_and_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = FakeTools(monkeypatch)
    tools.handlers["clamscan"] = _clamscan({})
    extra = "    maxDbAge: 12h\n"
    policy = _clamav_policy(tmp_path / "tools", pin=False, extra=extra)
    found = findings_of(
        inspect(write(tmp_path / "d", {"a": "x"}), policy_yaml=policy, plugins=True)
    )
    assert found["plugin.unpinned"][0].detail["unpinned"] == ["binary", "database"]
    assert found["plugin.data.stale"][0].detail["ageDays"] == 1
    assert "malware.detected" not in found  # it still ran, and the file was clean

    old = _clamav_policy(tmp_path / "tools2", extra="    minVersion: '1.5'\n")
    found = findings_of(inspect(write(tmp_path / "e", {"a": "x"}), policy_yaml=old, plugins=True))
    assert found["plugin.version.unsupported"][0].detail == {"version": "1.4.3", "minimum": "1.5"}
    assert found["malware.detected"][0].result is Result.NOT_ASSESSED

    missing = "plugins:\n  clamav: {path: /nowhere/clamscan, database: /nowhere, required: true}\n"
    result = inspect(write(tmp_path / "f", {"a": "x"}), policy_yaml=missing, plugins=True)
    assert "plugin.required.missing" in findings_of(result)
    assert result.assessment.plugins[0].present is False


def test_scanner_environment_has_no_way_out(tmp_path: Path) -> None:
    env = scrubbed_environment(tmp_path)
    assert env["HTTPS_PROXY"] == env["https_proxy"] == "http://127.0.0.1:9"
    assert env["NO_PROXY"] == ""
    assert env["HOME"] == env["USERPROFILE"] == str(tmp_path)
    assert not any(k.startswith("TRIVY_") for k in env)


# --- Trivy and KEV ------------------------------------------------------------------------------


def _vuln(
    vid: str, package: str, version: str, severity: str, **extra: object
) -> dict[str, object]:
    return {
        "VulnerabilityID": vid,
        "PkgName": package,
        "InstalledVersion": version,
        "FixedVersion": extra.pop("fixed", ""),
        "Severity": severity,
        "Title": f"{package} problem",
        **extra,
    }


def _trivy(fail_images: bool = False) -> Runner:
    def run(args: Sequence[str]) -> Completed:
        if args == ["--version"]:
            return Completed(0, "Version: 0.76.1\n", "")
        output = Path(args[args.index("--output") + 1])
        if args[0] == "image":
            if fail_images:
                return Completed(1, "", "FATAL image scan error")
            results = [
                {
                    "Target": "registry.example.org/team/app:1.0 (debian 12.7)",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        _vuln("CVE-2024-0001", "openssl", "3.0.14-1", "CRITICAL", fixed="3.0.15-1")
                    ],
                }
            ]
        elif args[0] == "sbom":
            sbom = json.loads(Path(args[1]).read_text(encoding="utf-8"))
            [tiny] = [c for c in sbom["components"] if c["name"] == "tinylib"]
            vuln = _vuln("GHSA-xxxx-yyyy-zzzz", "tinylib", "1.0.0", "MEDIUM")
            vuln["PkgIdentifier"] = {"PURL": tiny["purl"], "BOMRef": tiny["bom-ref"]}
            vuln["VendorIDs"] = ["CVE-2025-1111"]
            results = [{"Target": "delivery", "Type": "pip", "Vulnerabilities": [vuln]}]
        else:  # rootfs
            results = [{"Target": "rootfs", "Type": "debian", "Vulnerabilities": []}]
        output.write_text(json.dumps({"SchemaVersion": 2, "Results": results}), "utf-8")
        return Completed(0, "", "")

    return run


def _trivy_policy(tools: Path, *, kev: bool = True) -> str:
    binary, digest = _binary(tools, "trivy")
    cache = tools / "trivy-cache"
    (cache / "db").mkdir(parents=True)
    (cache / "db" / "trivy.db").write_bytes(b"bolt database")
    updated = (NOW - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    (cache / "db" / "metadata.json").write_text(json.dumps({"Version": 2, "UpdatedAt": updated}))
    text = (
        "plugins:\n  trivy:\n"
        f"    path: {binary.as_posix()}\n    database: {cache.as_posix()}\n"
        f"    binarySha256: {digest}\n"
        f"    files: {{db/trivy.db: {_sha(cache / 'db' / 'trivy.db')}, "
        f"db/metadata.json: {_sha(cache / 'db' / 'metadata.json')}}}\n"
    )
    if kev:
        catalogue = tools / "known_exploited_vulnerabilities.json"
        released = (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
        catalogue.write_text(
            json.dumps(
                {
                    "catalogVersion": "2026.11.10",
                    "dateReleased": released,
                    "vulnerabilities": [{"cveID": "CVE-2025-1111"}, {"cveID": "CVE-2023-9999"}],
                }
            )
        )
        text += (
            f"  kev:\n    path: {catalogue.as_posix()}\n    maxDbAge: 2d\n"
            f"    files: {{known_exploited_vulnerabilities.json: {_sha(catalogue)}}}\n"
        )
    return text


def _delivery(root: Path) -> Path:
    return write(
        root,
        {
            "images/app.tar": docker_archive(),
            f"wheels/{wheel_name()}": wheel_bytes(),
            "rootfs/etc/os-release": 'ID=debian\nVERSION_ID="12"\n',
            "rootfs/usr/bin/tool": "#!/bin/sh\n",
        },
    )


def test_trivy_scans_images_rootfs_and_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools(monkeypatch)
    tools.handlers["trivy"] = _trivy()
    policy = _trivy_policy(tmp_path / "tools")
    result = inspect(_delivery(tmp_path / "d"), policy_yaml=policy, plugins=True)
    found = findings_of(result)
    vulns = {f.attributes["id"]: f for f in found["vuln.component.known"]}

    image = vulns["CVE-2024-0001"]
    assert image.subject.display == "images/app.tar#openssl@3.0.14-1"
    assert image.severity is Severity.CRITICAL
    assert (image.attributes["fixed"], image.attributes["kev"]) == ("true", "false")

    package = vulns["GHSA-xxxx-yyyy-zzzz"]
    assert package.subject.artifact is not None
    assert package.subject.artifact.path == f"wheels/{wheel_name()}"
    assert package.attributes["kev"] == "true"  # through its CVE alias
    assert package.severity is Severity.MEDIUM

    runs = {c[0]: c for c in tools.commands("trivy") if c != ["--version"]}
    assert set(runs) == {"image", "rootfs", "sbom"}
    for command in runs.values():
        for flag in ("--skip-db-update", "--skip-java-db-update", "--offline-scan"):
            assert flag in command
    assert runs["rootfs"][1].endswith("rootfs")
    names = {s.name: s for s in result.assessment.plugins}
    assert names["trivy"].version == "0.76.1" and names["trivy"].data_age_seconds == 2 * 86400
    assert names["kev"].data_version == "2026.11.10"


def test_policy_can_block_on_kev_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = FakeTools(monkeypatch)
    tools.handlers["trivy"] = _trivy()
    policy = _trivy_policy(tmp_path / "tools") + (
        "rules:\n"
        "  - {rule: vuln.component.known, where: {kev: 'true'}, disposition: block}\n"
        "  - {rule: vuln.component.known, disposition: warn}\n"
    )
    result = inspect(_delivery(tmp_path / "d"), policy_yaml=policy, plugins=True)
    blocked = {d.finding for d in result.assessment.decisions if d.disposition.value == "block"}
    kev = [
        f.id for f in findings_of(result)["vuln.component.known"] if f.attributes["kev"] == "true"
    ]
    assert blocked == set(kev) and len(kev) == 1


def test_without_kev_findings_say_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = FakeTools(monkeypatch)
    tools.handlers["trivy"] = _trivy()
    policy = _trivy_policy(tmp_path / "tools", kev=False)
    found = findings_of(inspect(_delivery(tmp_path / "d"), policy_yaml=policy, plugins=True))
    assert {f.attributes["kev"] for f in found["vuln.component.known"]} == {"unknown"}


def test_a_failed_image_scan_is_not_a_clean_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools(monkeypatch)
    tools.handlers["trivy"] = _trivy(fail_images=True)
    policy = _trivy_policy(tmp_path / "tools")
    found = findings_of(inspect(_delivery(tmp_path / "d"), policy_yaml=policy, plugins=True))
    [error] = found["plugin.scan.error"]
    assert error.result is Result.ERROR and error.subject.display == "images/app.tar"
    gaps = [f for f in found["vuln.component.known"] if f.result is Result.NOT_ASSESSED]
    assert [g.subject.display for g in gaps] == ["images/app.tar"]
    assert any(f.result is Result.FAIL for f in found["vuln.component.known"])  # SBOM still ran


def test_trivy_without_a_database_does_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools(monkeypatch)
    binary, _ = _binary(tmp_path / "tools", "trivy")
    policy = f"plugins:\n  trivy: {{path: {binary.as_posix()}, required: true}}\n"
    result = inspect(write(tmp_path / "d", {"a": "x"}), policy_yaml=policy, plugins=True)
    found = findings_of(result)
    assert "database" in found["plugin.required.missing"][0].detail["reason"]
    assert tools.calls == []


def test_plugins_check_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from superscrubber104.cli import main

    tools = FakeTools(monkeypatch)
    tools.handlers["clamscan"] = _clamscan({})
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "apiVersion: superscrubber104/v1alpha1\nkind: Policy\nmetadata: {name: site, version: '1'}\n"
        + _clamav_policy(tmp_path / "tools"),
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, ["plugins", "check", "--policy", str(policy)])
    assert result.exit_code == 0, result.output
    assert "clamav   ready" in result.output
    assert "1.4.3" in result.output and "daily 27820" in result.output
    assert [c for c in tools.commands("clamscan")] == [["--version"]]  # nothing was scanned


def test_example_policy_configures_every_plugin() -> None:
    from superscrubber104.core.policy import load_policy

    policy = load_policy(Path(__file__).parent.parent / "examples" / "policy.yaml")
    assert set(policy.plugins) == {"clamav", "trivy", "kev", "semgrep", "bandit"}
    assert set(policy.runtimes) == {"llama-cpp"} and len(policy.compatibility) == 1
    assert policy.plugins["clamav"].database is not None


# --- static analysis ----------------------------------------------------------------------------


def _semgrep(args: Sequence[str]) -> Completed:
    if args == ["--version"]:
        return Completed(0, "1.86.0\n", "")
    files = [a for a in args if a.endswith((".py", ".ts"))]
    results = [
        {
            "check_id": "python.lang.security.audit.subprocess-shell-true",
            "path": f,
            "start": {"line": 3},
            "extra": {
                "severity": "ERROR",
                "message": "shell=True",
                "metadata": {"cwe": ["CWE-78"]},
            },
        }
        for f in files
        if f.endswith("main.py")
    ]
    output = Path(args[args.index("--output") + 1])
    output.write_text(json.dumps({"results": results, "errors": []}), encoding="utf-8")
    return Completed(0, "", "")


def _bandit(args: Sequence[str]) -> Completed:
    if args == ["--version"]:
        return Completed(0, "bandit 1.7.9\n  python version = 3.12\n", "")
    files = [a for a in args if a.endswith(".py")]
    results = [
        {
            "filename": f,
            "line_number": 1,
            "test_id": "B403",
            "test_name": "blacklist",
            "issue_severity": "LOW",
            "issue_confidence": "LOW",
            "issue_text": "Consider possible security implications of pickle.",
            "issue_cwe": {"id": 502},
        }
        for f in files
    ]
    output = Path(args[args.index("-o") + 1])
    output.write_text(json.dumps({"results": results, "errors": []}), encoding="utf-8")
    return Completed(1 if results else 0, "", "")


def _sast_policy(tools: Path) -> str:
    semgrep, semgrep_sha = _binary(tools, "semgrep")
    bandit, bandit_sha = _binary(tools, "bandit")
    rules = tools / "semgrep-rules"
    rules.mkdir()
    (rules / "python.yaml").write_text("rules: []\n")
    return (
        "plugins:\n"
        f"  semgrep:\n    path: {semgrep.as_posix()}\n    database: {rules.as_posix()}\n"
        f"    binarySha256: {semgrep_sha}\n    files: {{python.yaml: {_sha(rules / 'python.yaml')}}}\n"
        f"  bandit:\n    path: {bandit.as_posix()}\n    binarySha256: {bandit_sha}\n"
    )


def test_static_analysis_of_first_party_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import zipfile

    tools = FakeTools(monkeypatch)
    tools.handlers["semgrep"] = _semgrep
    tools.handlers["bandit"] = _bandit
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("project/run.py", "import os\n")
    root = write(
        tmp_path / "d",
        {
            "app/main.py": "import pickle\nimport subprocess\nsubprocess.run(cmd, shell=True)\n",
            "web/app.ts": "export const x = 1;\n",
            "venv/lib/python3.12/site-packages/lib/mod.py": "import pickle\n",
            "old/project.zip": zipped.getvalue(),
        },
    )
    result = inspect(root, policy_yaml=_sast_policy(tmp_path / "tools"), plugins=True)
    found = [f for f in findings_of(result)["sast.finding"]]
    fails = {
        (f.subject.display, f.attributes["scanner"]): f for f in found if f.result is Result.FAIL
    }
    assert set(fails) == {("app/main.py#line 3", "semgrep"), ("app/main.py#line 1", "bandit")}
    assert fails[("app/main.py#line 3", "semgrep")].severity is Severity.HIGH
    assert fails[("app/main.py#line 1", "bandit")].severity is Severity.INFO  # low, low confidence
    assert fails[("app/main.py#line 1", "bandit")].detail["cwe"] == "CWE-502"
    gaps = {f.subject.display for f in found if f.result is Result.NOT_ASSESSED}
    assert gaps == {"old/project.zip"}
    scanned = [a for c in tools.commands("semgrep") if c[0] == "scan" for a in c]
    assert not any("site-packages" in a for a in scanned)
    assert any(a.endswith("app.ts") for a in scanned) and "--metrics=off" in scanned


def test_sast_gap_only_when_there_is_source(tmp_path: Path) -> None:
    found = findings_of(inspect(write(tmp_path / "d", {"a.txt": "x"}), plugins=True))
    assert "sast.finding" not in found
    found = findings_of(inspect(write(tmp_path / "e", {"a.py": "x = 1\n"}), plugins=True))
    assert found["sast.finding"][0].result is Result.NOT_ASSESSED
