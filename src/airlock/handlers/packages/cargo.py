"""Rust: ``Cargo.lock``, ``.crate`` archives and ``cargo vendor`` directories.

* ``Cargo.lock`` lists every package with its source and, for registry packages, the sha256 of the
  ``.crate``. Each registry or git package must be satisfiable offline: a ``.crate`` in the delivery
  (a local registry) or a vendored directory.
* ``.crate`` files are hashed (that is the checksum ``Cargo.lock`` records) and their manifest read
  for build scripts and procedural macros, which run code at build time.
* A vendored crate's ``.cargo-checksum.json`` records the sha256 of every file and of the original
  ``.crate``. Cargo refuses to build a vendored crate whose files differ; so does this check
  (``package.checksum-mismatch``, final).
"""

import gzip
import re
import tarfile
import tomllib
from typing import IO, Any, cast
from urllib.parse import quote

from airlock import __version__
from airlock.archive import ARCHIVE_ERRORS, capped
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Component, LicenseRef, Subject, ToolRef, UnitClaim, UnitKind
from airlock.handlers.common import (
    TooLarge,
    mapping,
    name_of,
    read_json,
    read_text,
)
from airlock.handlers.packages.locked import (
    build_hooks,
    component,
    distribution_claim,
    lockfile_claim,
    requirement,
)

TOOL = ToolRef("airlock.cargo", __version__)
KIND = UnitKind.RUST_ENVIRONMENT
_CRATE = re.compile(r"^(?P<name>[A-Za-z0-9_-]+)-(?P<version>\d+\.\d+\.\d+[0-9A-Za-z.+-]*)\.crate$")
_V1_CHECKSUM = re.compile(r"^checksum (?P<name>\S+) (?P<version>\S+) \((?P<source>[^)]+)\)$")
_MANIFEST_LIMIT = 4 << 20
_CRATE_LIMIT = 512 << 20


def cargo_purl(name: str, version: str) -> str:
    return f"pkg:cargo/{quote(name)}@{quote(version, safe='')}"


def _hooks(manifest: dict[str, Any], has_build_rs: bool) -> list[str]:
    package = mapping(manifest.get("package"))
    hooks = []
    build = package.get("build")
    if (has_build_rs and build is not False) or isinstance(build, str):
        hooks.append("build-script")
    if mapping(manifest.get("lib")).get("proc-macro") or mapping(manifest.get("lib")).get(
        "proc_macro"
    ):
        hooks.append("proc-macro")
    return hooks


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref)
    if name == "Cargo.lock":
        return "cargo.lockfile"
    if name == ".cargo-checksum.json" and not view.ref.nested:
        return "cargo.vendored"
    if _CRATE.match(name) and view.head(2) == b"\x1f\x8b":
        return "cargo.crate"
    return None


class CargoHandler:
    name = "cargo"
    version = "1"
    kinds = frozenset({"cargo.lockfile", "cargo.crate", "cargo.vendored"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 90) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact)
        if kind == "cargo.lockfile":
            return self._lockfile(artifact)
        if kind == "cargo.crate":
            return self._crate(artifact, ctx)
        return self._vendored(artifact, ctx)

    def _lockfile(self, view: ArtifactView) -> Inspection:
        try:
            document = tomllib.loads(read_text(view, 64 << 20))
        except (tomllib.TOMLDecodeError, TooLarge) as exc:
            return Inspection(
                kind="cargo.lockfile", metadata={"cargoLock": {"error": str(exc)[:300]}}
            )
        legacy = {}  # lockfile v1 keeps checksums in [metadata]
        for key, value in mapping(document.get("metadata")).items():
            if (match := _V1_CHECKSUM.match(key)) and isinstance(value, str):
                legacy[(match["name"], match["version"])] = value
        requirements = []
        local = 0
        for package in document.get("package") or []:
            if not isinstance(package, dict):
                continue
            name, version = str(package.get("name", "")), str(package.get("version", ""))
            source = str(package.get("source") or "")
            if not source:
                local += 1  # a path dependency: source in the delivery, not a download
                continue
            checksum = package.get("checksum") or legacy.get((name, version))
            hashes = [f"sha256:{checksum}"] if isinstance(checksum, str) else []
            requirements.append(requirement(name, version, hashes))
        claim = lockfile_claim(view, KIND, "cargo", "Cargo.lock", requirements)
        summary = {
            "version": document.get("version", 1),
            "packages": len(requirements),
            "local": local,
        }
        return Inspection(kind="cargo.lockfile", metadata={"cargoLock": summary}, claims=(claim,))

    def _crate(self, view: ArtifactView, ctx: Context) -> Inspection:
        match = _CRATE.match(name_of(view.ref))
        assert match is not None  # noqa: S101 - detect() matched the name
        name, version = match["name"], match["version"]
        manifest: dict[str, Any] = {}
        has_build_rs = False
        try:
            with view.open() as raw, gzip.GzipFile(fileobj=raw) as expanded:
                # crates.io caps a crate at 10 MiB compressed; 512 MiB expanded is generous.
                bounded = capped(cast(IO[bytes], expanded), _CRATE_LIMIT)
                archive = tarfile.open(fileobj=bounded, mode="r|")  # noqa: SIM115 - closes with raw
                for member in archive:
                    parts = member.name.split("/")
                    if len(parts) == 2 and parts[1] == "build.rs":
                        has_build_rs = True
                    elif len(parts) == 2 and parts[1] == "Cargo.toml" and member.isfile():
                        handle = archive.extractfile(member)
                        if handle is not None and member.size <= _MANIFEST_LIMIT:
                            manifest = tomllib.loads(handle.read().decode("utf-8", "replace"))
        except (*ARCHIVE_ERRORS, tomllib.TOMLDecodeError) as exc:
            ctx.recorder.not_assessed(
                ("package.build-hooks",),
                Subject.of_artifact(view.ref),
                tool=TOOL,
                reason=f"the crate could not be read: {str(exc)[:200]}",
            )
            manifest, has_build_rs = {}, False
        hooks = _hooks(manifest, has_build_rs)
        build_hooks(view, ctx, TOOL, hooks)
        package = mapping(manifest.get("package"))
        purl = cargo_purl(name, version)
        licence = package.get("license")
        licences = (LicenseRef(expression=licence),) if isinstance(licence, str) and licence else ()
        part = component(view, name, version, purl, licenses=licences)
        claim = distribution_claim(
            view, KIND, "cargo", name, version, [f"sha256:{view.sha256}"], part.bom_ref
        )
        summary = {"name": name, "version": version, "licence": licence, "hooks": hooks}
        return Inspection(
            kind="cargo.crate", metadata={"crate": summary}, components=(part,), claims=(claim,)
        )

    def _vendored(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            checksums = mapping(read_json(view, 64 << 20))
        except (TooLarge, ValueError) as exc:
            return Inspection(
                kind="cargo.vendored", metadata={"vendoredCrate": {"error": str(exc)[:300]}}
            )
        manifest_view = view.resolve("Cargo.toml")
        manifest: dict[str, Any] = {}
        if manifest_view is not None:
            try:
                manifest = tomllib.loads(read_text(manifest_view, _MANIFEST_LIMIT))
            except (tomllib.TOMLDecodeError, TooLarge):
                manifest = {}
        package = mapping(manifest.get("package"))
        name, version = str(package.get("name", "")), str(package.get("version", ""))
        files = mapping(checksums.get("files"))
        modified, missing = [], []
        for path, expected in sorted(files.items()):
            target = view.resolve(path)
            if target is None:
                missing.append(path)
            elif target.sha256 != str(expected).lower():
                modified.append(path)
        subject = Subject.of_artifact(view.ref)
        if modified or missing:
            ctx.recorder.fail(
                "package.checksum-mismatch",
                subject,
                tool=TOOL,
                detail={
                    "crate": f"{name}@{version}",
                    "modified": modified[:100],
                    "missing": missing[:100],
                },
            )
        elif files:
            ctx.recorder.passed("package.checksum-mismatch")
        hooks = _hooks(manifest, "build.rs" in files)
        build_hooks(view, ctx, TOOL, hooks)
        crate_hash = checksums.get("package")
        hashes = [f"sha256:{crate_hash}"] if isinstance(crate_hash, str) else []
        claims: tuple[UnitClaim, ...] = ()
        components: tuple[Component, ...] = ()
        if name and version:
            part = component(view, name, version, cargo_purl(name, version))
            components = (part,)
            claims = (distribution_claim(view, KIND, "cargo", name, version, hashes, part.bom_ref),)
        summary = {
            "name": name,
            "version": version,
            "files": len(files),
            "modified": len(modified),
            "hooks": hooks,
        }
        return Inspection(
            kind="cargo.vendored",
            metadata={"vendoredCrate": summary},
            components=components,
            claims=claims,
        )
