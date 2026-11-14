"""Running an external scanner without trusting it.

Before a scanner touches content, airlock establishes which scanner it is: the binary and every
pinned database file are hashed and compared with the policy, the version is read and compared
with the policy's minimum, and the age of the database is read from the database itself. A
scanner that fails any of this does not run, and the checks it would have made are recorded as
not assessed.

Scanners run as child processes with an argument list (never a shell), no standard input, a
private working directory and a cleaned environment. Proxy variables point at a closed local
port, so a scanner that tries to reach the network fails fast instead of leaving the enclave;
the host should have no route out anyway.
"""

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

from airlock import __version__
from airlock.core.interfaces import Context
from airlock.core.model import (
    Analysis,
    ArtifactRef,
    PluginStatus,
    Subject,
    SubjectKind,
    ToolRef,
)
from airlock.core.policy import PluginPolicy
from airlock.hashing import hash_file

TOOL = ToolRef("airlock.scanners", __version__)
_OUTPUT_LIMIT = 512 << 20
_CLOSED_PORT = "http://127.0.0.1:9"  # discard port: nothing listens, connections are refused
_KEEP_ENV = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "LANG", "LC_ALL", "TZ")


class ScanError(Exception):
    """The scanner ran but did not produce a usable result."""


@dataclass(frozen=True, slots=True)
class Target:
    """A top-level file of the delivery, on disk where the scanner can read it."""

    ref: ArtifactRef
    location: Path
    size: int


@dataclass(frozen=True, slots=True)
class DataInfo:
    """What a scanner's database says about itself."""

    version: str | None = None
    built_at: datetime | None = None
    files: tuple[str, ...] = ()  # files that are part of the database (for pinning checks)
    problem: str | None = None  # the database is missing or unreadable


@dataclass(frozen=True, slots=True)
class Ready:
    """A scanner that passed every pre-flight check."""

    name: str
    binary: Path | None
    policy: PluginPolicy
    status: PluginStatus
    workdir: Path
    tool: ToolRef

    def run(self, args: Sequence[str], *, ok: Sequence[int] = (0,)) -> "Completed":
        assert self.binary is not None  # noqa: S101 - data-only plugins never run
        return run_process(
            [str(self.binary), *args],
            timeout=self.policy.timeout.total_seconds(),
            workdir=self.workdir,
            ok=ok,
        )


@dataclass(frozen=True, slots=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


def plugin_subject(name: str) -> Subject:
    return Subject(SubjectKind.POLICY, locator=f"plugins.{name}")


def scrubbed_environment(workdir: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in _KEEP_ENV}
    home = str(workdir)
    env.update(
        {
            "HOME": home,
            "USERPROFILE": home,
            "TMP": home,
            "TEMP": home,
            "TMPDIR": home,
            "XDG_CACHE_HOME": home,
            "XDG_CONFIG_HOME": home,
            "HTTP_PROXY": _CLOSED_PORT,
            "HTTPS_PROXY": _CLOSED_PORT,
            "ALL_PROXY": _CLOSED_PORT,
            "http_proxy": _CLOSED_PORT,
            "https_proxy": _CLOSED_PORT,
            "all_proxy": _CLOSED_PORT,
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    return env


def run_process(
    command: Sequence[str], *, timeout: float, workdir: Path, ok: Sequence[int] = (0,)
) -> Completed:
    """Run one scanner command. Raises ScanError on a timeout or an unexpected exit code."""
    out_path = workdir / f"stdout-{len(list(workdir.glob('stdout-*')))}.txt"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        with out_path.open("wb") as out:
            proc = subprocess.run(  # noqa: S603 - argument list, no shell
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.PIPE,
                cwd=workdir,
                env=scrubbed_environment(workdir),
                timeout=timeout,
                check=False,
                creationflags=flags,
            )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"timed out after {int(timeout)}s") from exc
    except OSError as exc:
        raise ScanError(f"could not start: {exc}") from exc
    if out_path.stat().st_size > _OUTPUT_LIMIT:
        raise ScanError("output is larger than airlock will read")
    stdout = out_path.read_bytes().decode("utf-8", "replace")
    stderr = proc.stderr[-65536:].decode("utf-8", "replace")
    if proc.returncode not in ok:
        tail = (stderr.strip() or stdout.strip())[-500:]
        raise ScanError(f"exit code {proc.returncode}: {tail}")
    return Completed(proc.returncode, stdout, stderr)


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:4])


class Scanner(Protocol):
    """An external tool wrapped as a plugin.

    ``capability`` groups scanners that answer the same question; when no scanner of a
    capability runs, its ``rules`` are recorded as not assessed for the whole delivery.
    """

    name: str
    capability: str
    rules: tuple[str, ...]
    binary_names: tuple[str, ...]  # looked up on PATH when the policy gives no path; () = data

    def version(self, ready: "Ready") -> str | None: ...

    def data(self, policy: PluginPolicy) -> DataInfo: ...

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None: ...


@dataclass(slots=True)
class Preflight:
    """Establishes whether a configured scanner may run, recording why not if it may not."""

    scanner: Scanner
    policy: PluginPolicy
    ctx: Context
    workdir: Path
    problems: list[str] = field(default_factory=list)

    def _fail(self, rule: str, detail: Mapping[str, object], discriminator: str = "") -> None:
        self.ctx.recorder.fail(
            rule,
            plugin_subject(self.scanner.name),
            tool=TOOL,
            detail=detail,
            attributes={"plugin": self.scanner.name},
            discriminator=discriminator,
        )

    def binary(self) -> Path | None:
        if self.policy.path is not None:
            return self.policy.path if self.policy.path.is_file() else None
        for name in self.scanner.binary_names:
            found = shutil.which(name)
            if found:
                return Path(found)
        return None

    def run(self) -> tuple[PluginStatus, Ready | None]:
        name, policy, recorder = self.scanner.name, self.policy, self.ctx.recorder
        data_only = not self.scanner.binary_names
        binary = None if data_only else self.binary()
        if not data_only and binary is None:
            names = ", ".join(self.scanner.binary_names)
            where = str(policy.path) if policy.path else f"PATH ({names})"
            return self._absent(f"scanner not found at {where}")

        binary_sha = hash_file(binary).sha256 if binary is not None else None
        unpinned: list[str] = []
        if binary_sha is not None:
            if policy.binary_sha256 is None:
                unpinned.append("binary")
            elif policy.binary_sha256 != binary_sha:
                self._fail(
                    "plugin.integrity.mismatch",
                    {"file": str(binary), "expected": policy.binary_sha256, "actual": binary_sha},
                    discriminator="binary",
                )
                return self._refused(binary_sha, "the scanner binary does not match its pin")

        info = self.scanner.data(policy)
        if info.problem:
            return self._absent(info.problem, binary_sha=binary_sha)
        if not self._data_pins(info, unpinned):
            return self._refused(binary_sha, "the scanner database does not match its pins")

        status = PluginStatus(
            name=name,
            present=True,
            binary_sha256=binary_sha,
            pinned=not unpinned,
            data_version=info.version,
            data_age_seconds=self._age(info),
        )
        ready = Ready(name, binary, policy, status, self.workdir, ToolRef(name, "unknown"))
        version = None
        if binary is not None:
            try:
                version = self.scanner.version(ready)
            except ScanError as exc:
                self._fail("plugin.scan.error", {"step": "version", "error": str(exc)})
                return self._absent(f"could not read the scanner version: {exc}", binary_sha)
        if (
            version
            and policy.min_version
            and version_tuple(version) < version_tuple(policy.min_version)
        ):
            self._fail(
                "plugin.version.unsupported", {"version": version, "minimum": policy.min_version}
            )
            return self._absent(f"version {version} is below {policy.min_version}", binary_sha)
        recorder.passed("plugin.version.unsupported")
        if unpinned:
            self._fail("plugin.unpinned", {"unpinned": unpinned})
        else:
            recorder.passed("plugin.unpinned")
        self._freshness(info, status.data_age_seconds)
        status = PluginStatus(
            name=name,
            present=True,
            version=version,
            binary_sha256=binary_sha,
            pinned=not unpinned,
            data_version=info.version,
            data_age_seconds=status.data_age_seconds,
        )
        extra = {"dbVersion": info.version} if info.version else None
        tool = ToolRef(name, version or "unknown", extra)
        return status, Ready(name, binary, policy, status, self.workdir, tool)

    def _data_pins(self, info: DataInfo, unpinned: list[str]) -> bool:
        policy = self.policy
        if not policy.files:
            if info.files:
                unpinned.append("database")
            return True
        base = policy.database or (policy.path.parent if policy.path else Path())
        bad: list[dict[str, object]] = []
        for relative, expected in sorted(policy.files.items()):
            path = base / relative
            actual = hash_file(path).sha256 if path.is_file() else None
            if actual != expected:
                bad.append({"file": relative, "expected": expected, "actual": actual})
        extra = sorted(set(info.files) - set(policy.files))
        for relative in extra:  # it would be loaded, but nobody pinned it
            bad.append({"file": relative, "expected": None, "actual": "present, not pinned"})
        if bad:
            self._fail("plugin.integrity.mismatch", {"files": bad}, discriminator="data")
            return False
        return True

    def _age(self, info: DataInfo) -> int | None:
        if info.built_at is None:
            return None
        return max(0, int((self.ctx.now - info.built_at).total_seconds()))

    def _freshness(self, info: DataInfo, age: int | None) -> None:
        limit = self.policy.max_db_age
        if limit is None:
            return
        if age is None:
            self.ctx.recorder.not_assessed(
                ("plugin.data.stale",),
                plugin_subject(self.scanner.name),
                tool=TOOL,
                reason="the database does not record when it was built",
            )
        elif age > limit.total_seconds():
            self._fail(
                "plugin.data.stale",
                {
                    "builtAt": info.built_at.isoformat() if info.built_at else None,
                    "ageDays": age // 86400,
                    "maxAgeDays": int(limit.total_seconds()) // 86400,
                    "dataVersion": info.version,
                },
            )
        else:
            self.ctx.recorder.passed("plugin.data.stale")

    def _absent(self, reason: str, binary_sha: str | None = None) -> tuple[PluginStatus, None]:
        if self.policy.required:
            self._fail("plugin.required.missing", {"reason": reason})
        return PluginStatus(
            self.scanner.name, present=False, binary_sha256=binary_sha, reason=reason
        ), None

    def _refused(self, binary_sha: str | None, reason: str) -> tuple[PluginStatus, None]:
        return PluginStatus(
            self.scanner.name, present=True, binary_sha256=binary_sha, pinned=False, reason=reason
        ), None


def files_under(root: Path, accept: Callable[[Path], bool]) -> tuple[str, ...]:
    """Relative POSIX paths of the files under ``root`` that ``accept`` selects."""
    if not root.is_dir():
        return ()
    return tuple(
        sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and accept(p))
    )
