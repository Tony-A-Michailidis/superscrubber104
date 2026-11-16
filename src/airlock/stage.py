"""``airlock stage``: place verified content into the receiving side's repositories and stores.

Staging only ever copies what was just verified and accepted:

1. The ledger must already hold an accepted receipt for exactly this manifest (``airlock verify
   --state`` first).
2. The bundle is verified again, without touching the ledger, so the units to stage come from
   this side's own analysis, never the packer's. It is judged as of the moment it was accepted:
   a bundle does not become unstageable because time has passed, but a policy that has since
   changed its mind (a revoked key, a new rule) stops it.
3. Every file is re-hashed while it is copied and compared with the manifest; it is moved into
   place only if it matches, so nothing changed between verification and staging can land.
   Existing files are never overwritten: identical ones are skipped, different ones are an error.
4. The stage report is written under the state directory and a signed ``stage`` event goes into
   the ledger with its digest. A staging that fails part-way is recorded too, with what had
   already been copied.

Targets lay content out the way the receiving tools expect it. airlock writes files and indexes;
it never pushes to a registry or calls a service (no network at runtime): the report names the
command that finishes the job where one is needed (``skopeo copy``, ``createrepo_c``).
"""

import base64
import hashlib
import html
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from airlock import bundle as layout
from airlock.core import chainlog
from airlock.core.canonical import sha256_digest
from airlock.core.errors import AirlockError, ConfigError
from airlock.core.model import API_VERSION, Artifact, ArtifactRef, UnitKind, Verdict
from airlock.core.policy import KeyRole, Policy
from airlock.core.signing import Signer, VerifyKey
from airlock.handlers.common import relative_to
from airlock.ledger import Ledger
from airlock.verify import Verified, verify

EVENT_STAGE = "stage"
TARGETS = ("files", "models", "pypi", "npm", "dnf", "apt", "oci", "windows")
_WINDOWS = (".msu", ".cab", ".msi", ".exe", ".msix", ".appx")


class StageError(AirlockError):
    pass


@dataclass(slots=True)
class TargetReport:
    kind: str
    destination: str
    copied: int = 0
    present: int = 0
    items: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class StageReport:
    bundle_id: str | None
    manifest_digest: str
    staged_at: datetime
    targets: tuple[TargetReport, ...]
    downgrades_allowed: str | None = None
    failed: str | None = None  # why staging stopped part-way, if it did
    api_version: str = API_VERSION
    kind: str = "StageReport"


@dataclass(frozen=True, slots=True)
class Staged:
    report: StageReport
    path: Path  # where the report was written


class _Stager:
    """Copies verified files under one destination, re-hashing each against the manifest."""

    def __init__(self, verified: Verified, kind: str, destination: Path) -> None:
        self.verified, self.destination = verified, destination
        self.report = TargetReport(kind, destination.as_posix())
        self.expected = {e.path: e.sha256 for e in verified.manifest.entries if e.sha256}

    def copy(self, path: str, relative: str) -> Path:
        view = self.verified.files.get(path)
        expected = self.expected.get(path)
        if view is None or expected is None:
            raise StageError(f"{path} is not a verified file of this bundle")
        target = (self.destination / PurePosixPath(relative)).resolve()
        if not target.is_relative_to(self.destination.resolve()):
            raise StageError(f"{relative} would leave {self.destination}")
        partial = target.with_name(target.name + ".airlock-partial")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if _sha256(target) != expected:
                    raise StageError(f"{target} already exists with different content")
                self.report.present += 1
                return target
            partial.unlink(missing_ok=True)  # left by a staging that was interrupted
            digest = hashlib.sha256()
            with view.location.open("rb") as source, partial.open("xb") as sink:
                while block := source.read(1 << 20):
                    digest.update(block)
                    sink.write(block)
                sink.flush()
                os.fsync(sink.fileno())
            if digest.hexdigest() != expected:
                partial.unlink()
                raise StageError(
                    f"{path} changed after it was verified; nothing was staged from it"
                )
            partial.replace(target)
        except OSError as exc:
            partial.unlink(missing_ok=True)
            raise StageError(f"could not stage {path} to {target}: {exc}") from exc
        self.report.copied += 1
        return target


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def _top(ref: ArtifactRef) -> str:
    return ref.path


def _artifacts(verified: Verified, accept: Callable[[Artifact], bool]) -> list[Artifact]:
    return [a for a in verified.analysis.artifacts if not a.ref.nested and accept(a)]


def _under(root: ArtifactRef, files: Iterable[str]) -> list[tuple[str, str]]:
    out = []
    for path in sorted(files):
        below = relative_to(ArtifactRef(path), root)
        if below is not None:
            out.append((path, below))
    return out


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "unit"


# --- targets ------------------------------------------------------------------------------------


def stage_files(s: _Stager) -> None:
    for path in sorted(s.verified.files):
        s.copy(path, path)
    s.report.items.append(f"{len(s.verified.files)} files")


def stage_models(s: _Stager) -> None:
    for unit in s.verified.analysis.units:
        if unit.kind is not UnitKind.MODEL_PACKAGE:
            continue
        name = _safe(unit.root.display.rsplit("/", 1)[-1] if unit.root.path != "." else unit.name)
        members = sorted({_top(m.artifact) for m in unit.members})
        for path in members:
            below = relative_to(ArtifactRef(path), unit.root) if not unit.root.nested else None
            s.copy(path, f"{name}/{below or PurePosixPath(path).name}")
        s.report.items.append(name)


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dist_name(filename: str) -> str | None:
    if filename.endswith(".whl"):
        return _pep503(filename.split("-", 1)[0])
    for suffix in (".tar.gz", ".zip", ".tar.bz2"):
        if filename.endswith(suffix):
            return _pep503(filename[: -len(suffix)].rsplit("-", 1)[0])
    return None


def stage_pypi(s: _Stager) -> None:
    """A PEP 503 simple index: ``packages/`` plus ``simple/<project>/index.html`` with hashes."""
    for artifact in _artifacts(
        s.verified, lambda a: {"python.wheel", "python.sdist"} & set(a.kinds) != set()
    ):
        s.copy(artifact.ref.path, f"packages/{PurePosixPath(artifact.ref.path).name}")
    projects: dict[str, list[tuple[str, str]]] = {}
    packages = s.destination / "packages"
    for file in sorted(packages.iterdir()) if packages.is_dir() else []:
        if (project := _dist_name(file.name)) and not file.name.endswith(".airlock-partial"):
            projects.setdefault(project, []).append((file.name, _sha256(file)))
    for project, files in projects.items():
        links = "".join(
            f'<a href="../../packages/{html.escape(n)}#sha256={sha}">{html.escape(n)}</a><br/>\n'
            for n, sha in files
        )
        _write(
            s.destination / "simple" / project / "index.html",
            f"<!DOCTYPE html>\n<html><body>\n{links}</body></html>\n",
        )
    root_links = "".join(f'<a href="{p}/">{p}</a><br/>\n' for p in sorted(projects))
    _write(
        s.destination / "simple" / "index.html",
        f"<!DOCTYPE html>\n<html><body>\n{root_links}</body></html>\n",
    )
    s.report.items.extend(sorted(projects))
    s.report.notes.append(
        f"pip install --no-index --find-links {packages.as_posix()} ... or serve simple/"
    )


def stage_npm(s: _Stager) -> None:
    """Verdaccio-style storage: ``<name>/<file>.tgz`` and a packument per package."""
    for artifact in _artifacts(s.verified, lambda a: "npm.tarball" in a.kinds):
        meta = artifact.metadata.get("npmTarball")
        if not isinstance(meta, dict) or not meta.get("name") or not meta.get("version"):
            continue
        name, version = str(meta["name"]), str(meta["version"])
        file = f"{name.rsplit('/', 1)[-1]}-{version}.tgz"
        target = s.copy(artifact.ref.path, f"{name}/{file}")
        data = target.read_bytes()
        packument_path = s.destination / name / "package.json"
        packument: dict[str, Any] = {"name": name, "versions": {}, "dist-tags": {}}
        if packument_path.is_file():
            packument = json.loads(packument_path.read_text(encoding="utf-8"))
        packument["versions"][version] = {
            "name": name,
            "version": version,
            "dist": {
                "tarball": f"http://localhost:4873/{name}/-/{file}",
                "shasum": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
                "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
            },
        }
        packument["dist-tags"]["latest"] = max(packument["versions"], key=_semver_key)
        _write(packument_path, json.dumps(packument, indent=2, sort_keys=True) + "\n")
        s.report.items.append(f"{name}@{version}")
    s.report.notes.append(
        "point Verdaccio's storage at this directory (tarball URLs are rewritten on serve)"
    )


def _semver_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version.split("-", 1)[0])[:3])


def _repo_stager(fmt: str, suffix: str, local: str, finish: str) -> Callable[[_Stager], None]:
    def run(s: _Stager) -> None:
        covered: set[str] = set()
        for unit in s.verified.analysis.units:
            if unit.kind is not UnitKind.REPO_MIRROR or unit.attributes.get("format") != fmt:
                continue
            name = unit.root.path if unit.root.path != "." else fmt
            for path, below in _under(unit.root, s.verified.files):
                s.copy(path, f"{name}/{below}")
                covered.add(path)
            s.report.items.append(f"mirror {name} (vendor metadata and signatures kept)")
        loose = [
            a
            for a in _artifacts(s.verified, lambda a: a.ref.path.endswith(suffix))
            if a.ref.path not in covered
        ]
        for artifact in loose:
            s.copy(artifact.ref.path, f"{local}/{PurePosixPath(artifact.ref.path).name}")
        if loose:
            s.report.items.append(f"{len(loose)} loose packages in {local}")
            s.report.notes.append(finish.format(dest=(s.destination / local).as_posix()))

    return run


stage_dnf = _repo_stager(
    "dnf",
    ".rpm",
    "local/Packages",
    "createrepo_c --update {dest}/..  (then sign repomd.xml with the site key)",
)
stage_apt = _repo_stager(
    "apt",
    ".deb",
    "local/pool",
    "build the index with reprepro or aptly from {dest}, signed with the site key",
)


def stage_oci(s: _Stager) -> None:
    for unit in s.verified.analysis.units:
        if unit.kind is not UnitKind.CONTAINER_IMAGE:
            continue
        name = _safe(unit.name)
        paths = sorted({_top(m.artifact) for m in unit.members})
        for path in paths:
            below = (
                relative_to(ArtifactRef(path), unit.root)
                if not unit.root.nested and unit.root.path != path
                else None
            )
            s.copy(path, f"{name}/{below or PurePosixPath(path).name}")
        s.report.items.append(unit.name)
        s.report.notes.append(
            f"skopeo copy <oci:|docker-archive:>{(s.destination / name).as_posix()} docker://<registry>/{unit.name}"
        )


def stage_windows(s: _Stager) -> None:
    for artifact in _artifacts(s.verified, lambda a: a.ref.path.lower().endswith(_WINDOWS)):
        s.copy(artifact.ref.path, PurePosixPath(artifact.ref.path).name)
        s.report.items.append(PurePosixPath(artifact.ref.path).name)
    s.report.notes.append("import into WSUS (wsusutil) or deploy from this share")


STAGERS: Mapping[str, Callable[[_Stager], None]] = {
    "files": stage_files,
    "models": stage_models,
    "pypi": stage_pypi,
    "npm": stage_npm,
    "dnf": stage_dnf,
    "apt": stage_apt,
    "oci": stage_oci,
    "windows": stage_windows,
}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- the command --------------------------------------------------------------------------------


def _accepted_at(ledger: Ledger, bundle: Path) -> tuple[str, datetime]:
    """The manifest digest of ``bundle`` and when this side accepted it."""
    try:
        digest = sha256_digest((bundle / layout.MANIFEST).read_bytes())
    except OSError as exc:
        raise StageError(f"not a readable bundle: {exc}") from exc
    times = [r.verified_at for r in ledger.accepted if r.manifest_digest == digest]
    if not times:
        raise StageError(
            "this bundle has not been accepted on this side: run airlock verify --state first"
        )
    return digest, max(times)


def stage(
    bundle: Path,
    *,
    policy: Policy,
    state: Path,
    targets: Mapping[str, Path],
    now: datetime,
    signer: Signer | None = None,
    pubkey: VerifyKey | None = None,
    volume_dirs: Iterable[Path] = (),
    bases: Iterable[Path] = (),
    check: Callable[[Verified], str | None] | None = None,
) -> Staged:
    """Stage ``bundle`` into ``targets`` (kind -> destination directory).

    ``check`` may refuse the staging after verification (by raising ``StageError``) or allow it
    with a note kept in the report; ``airlock patch stage`` uses it for downgrade protection.
    """
    unknown = sorted(set(targets) - set(TARGETS))
    if unknown:
        raise ConfigError(
            f"unknown stage target(s): {', '.join(unknown)} (known: {', '.join(TARGETS)})"
        )
    if not targets:
        raise ConfigError("give at least one --target")
    signed = bool(policy.signers_with_role(KeyRole.RECEIPT))
    if signed and signer is None:
        raise ConfigError("the policy pins a receipt key: give --key to sign the stage event")
    ledger = Ledger(state)
    resolve = {s.key_id: s.load() for s in policy.signers}
    problems = ledger.load(resolve.get, require_signed=signed)
    if problems:
        raise StageError(f"the ledger does not verify: {problems[0]}")
    accepted_digest, accepted_at = _accepted_at(ledger, bundle)
    reports: list[TargetReport] = []
    outcome: dict[str, str | None] = {}

    def use(verified: Verified) -> None:
        if verified.manifest_digest != accepted_digest:
            raise StageError("the manifest is not the one the signed statement covers")
        if verified.assessment.summary.verdict is not Verdict.PASSED:
            verdict = verified.assessment.summary.verdict.value
            raise StageError(f"the bundle no longer passes verification ({verdict})")
        outcome["bundle"] = verified.bundle_id
        outcome["note"] = check(verified) if check is not None else None
        for kind, destination in sorted(targets.items()):
            stager = _Stager(verified, kind, destination)
            reports.append(stager.report)  # kept even if this target fails part-way
            try:
                destination.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise StageError(f"cannot create {destination}: {exc}") from exc
            STAGERS[kind](stager)

    failure: StageError | None = None
    try:
        # As of the acceptance: the passing of time alone does not undo an import.
        verify(
            bundle,
            policy=policy,
            pubkey=pubkey,
            now=accepted_at,
            volume_dirs=tuple(volume_dirs),
            bases=tuple(bases),
            use=use,
        )
    except StageError as exc:
        if not reports:
            raise  # nothing was touched: nothing to record
        failure = exc
    if "bundle" not in outcome:
        raise StageError("the bundle could not be verified far enough to stage anything")
    report = StageReport(
        bundle_id=outcome["bundle"],
        manifest_digest=accepted_digest,
        staged_at=now,
        targets=tuple(reports),
        downgrades_allowed=outcome.get("note"),
        failed=str(failure) if failure else None,
    )
    encoded = layout.encode(report)
    directory = state / "stages" / f"{now:%Y%m%dT%H%M%SZ}-{(report.bundle_id or 'bundle')[:12]}"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "stage-report.json"
        path.write_bytes(encoded)
    except OSError as exc:
        raise StageError(f"could not write the stage report: {exc}") from exc
    chainlog.append(
        ledger.path,
        EVENT_STAGE,
        {
            "bundleId": report.bundle_id,
            "manifestDigest": report.manifest_digest,
            "reportDigest": sha256_digest(encoded),
            "outcome": "failed" if failure else "staged",
            "targets": {t.kind: {"copied": t.copied, "present": t.present} for t in reports},
        },
        now=now,
        signer=signer,
    )
    if failure is not None:
        raise failure
    return Staged(report, path)
