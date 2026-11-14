"""Python environments: can the delivery satisfy each lockfile offline?

For every lockfile, each locked requirement must be met by a distribution (wheel or sdist)
somewhere in the delivery, with the locked version and, when the lockfile records hashes, a hash
the lockfile names. That is what ``pip install --no-index --require-hashes`` against a local
wheelhouse needs; finding a gap before transfer is cheaper than finding it on the other side.

Installed packages (site-packages of a virtualenv, a prefix such as ``/usr/local``, a container
layer) form one environment per installation prefix: an inventory, not a resolution.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Sequence

from airlock import __version__
from airlock.checks.allowlists import check_allowlist
from airlock.core.canonical import JSON
from airlock.core.interfaces import Assembly, Context
from airlock.core.model import (
    ArtifactRef,
    Severity,
    Subject,
    SubjectKind,
    ToolRef,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
)
from airlock.handlers.common import name_of
from airlock.handlers.packages.python import canon_name, canon_version
from airlock.units.facts import as_dict, as_str, dicts, strings

TOOL = ToolRef("airlock.python-environment", __version__)
_OS = (
    ("windows", re.compile(r"^win")),
    ("macos", re.compile(r"^macosx")),
    ("linux", re.compile(r"linux")),
)


def _platform(tag: str) -> str | None:
    if tag == "any":
        return None
    for family, pattern in _OS:
        if any(pattern.search(t) for t in tag.split(".")):
            return family
    return tag


def _subject(root: ArtifactRef) -> Subject:
    return Subject(SubjectKind.UNIT, unit=f"{UnitKind.PYTHON_ENVIRONMENT.value}:{root.display}")


def _members(claims: Iterable[UnitClaim]) -> tuple[UnitMember, ...]:
    unique = {(c.artifact, c.role): c.sha256 for c in claims}
    return tuple(UnitMember(role, ref, sha) for (ref, role), sha in sorted(unique.items()))


class PythonEnvironmentAssembler:
    name = "python-environment"
    version = "1"
    kind = UnitKind.PYTHON_ENVIRONMENT

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        distributions: dict[str, list[UnitClaim]] = defaultdict(list)
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for c in claims:
            if c.role == "distribution":
                distributions[str(c.facts.get("name"))].append(c)
            elif c.role in ("lockfile", "installed", "venv"):
                groups[c.root].append(c)
        assemblies = []
        for root, group in sorted(groups.items()):
            lockfile = next((c for c in group if c.role == "lockfile"), None)
            if lockfile is not None:
                assemblies.append(_Resolution(root, lockfile, distributions, ctx).run())
            else:
                assemblies.append(_installed(root, group, ctx))
        return assemblies


class _Resolution:
    """Resolve one lockfile against the distributions in the delivery."""

    def __init__(
        self,
        root: ArtifactRef,
        lock: UnitClaim,
        distributions: dict[str, list[UnitClaim]],
        ctx: Context,
    ) -> None:
        self.root = root
        self.lock = lock
        self.distributions = distributions
        self.ctx = ctx
        self.used: list[UnitClaim] = []
        self.missing: list[dict[str, JSON]] = []
        self.conditional: list[dict[str, JSON]] = []
        self.mismatched = 0
        self.platforms: set[str] = set()
        self.pythons: set[str] = set()
        self.local_versions: set[str] = set()

    def run(self) -> Assembly:
        everything = dicts(self.lock.facts.get("requirements"))
        requirements = [r for r in everything if r.get("source") == "index"]
        for req in requirements:
            self._resolve(req)
        self._report()
        packages = [(str(r.get("displayName")), as_str(r.get("version"))) for r in requirements]
        check_allowlist(
            self.ctx, "python", packages, _subject(self.root), canon_name, canon_version
        )
        unresolvable: list[JSON] = [m.get("name") for m in self.missing][:200]
        conditional: list[JSON] = [m.get("name") for m in self.conditional][:200]
        attributes: dict[str, JSON] = {
            "lockfile": name_of(self.lock.artifact),
            "format": self.lock.facts.get("format"),
            "requirements": len(everything),
            "resolved": len(requirements) - len(self.missing) - len(self.conditional),
            "unresolvable": unresolvable,
            "conditionalUnresolvable": conditional,
            "hashed": bool(requirements) and all(r.get("hashes") for r in requirements),
            "platforms": list(sorted(self.platforms)),
            "pythonTags": list(sorted(self.pythons)),
            "localVersions": list(sorted(self.local_versions)),
        }
        bom_refs = {b for d in self.used if (b := as_str(d.facts.get("bomRef")))}
        unit = Unit(
            kind=UnitKind.PYTHON_ENVIRONMENT,
            name=f"python environment ({name_of(self.lock.artifact)})",
            root=self.root,
            members=_members([self.lock, *self.used]),
            components=tuple(sorted(bom_refs)),
            attributes=attributes,
        )
        return Assembly(unit)

    def _resolve(self, req: dict[str, JSON]) -> None:
        name, version = str(req.get("name")), as_str(req.get("version"))
        candidates = [
            d
            for d in self.distributions.get(name, [])
            if version is None or d.facts.get("version") == version
        ]
        if not candidates:
            entry: dict[str, JSON] = {
                "name": req.get("displayName"),
                "version": version,
                "markers": req.get("markers"),
            }
            (self.conditional if req.get("markers") else self.missing).append(entry)
            return
        hashes = set(strings(req.get("hashes")))
        matching = [d for d in candidates if not hashes or d.sha256 in hashes]
        if not matching:
            for d in candidates:
                self.mismatched += 1
                self.ctx.recorder.fail(
                    "python.environment.hash-mismatch",
                    Subject.of_artifact(d.artifact),
                    tool=TOOL,
                    detail={
                        "requirement": req.get("displayName"),
                        "version": version,
                        "lockfile": self.lock.artifact.display,
                        "actual": d.sha256,
                        "locked": sorted(hashes)[:10],
                    },
                )
            return
        for d in matching:
            self.used.append(d)
            tags = as_dict(d.facts.get("tags"))
            family = _platform(str(tags.get("platform", "any"))) if tags else None
            if family:
                self.platforms.add(family)
            python = str(tags.get("python", ""))
            if python.startswith("cp"):
                self.pythons.add(python)
            local = as_str(d.facts.get("local"))
            if local:
                self.local_versions.add(local)

    def _report(self) -> None:
        recorder, subject = self.ctx.recorder, _subject(self.root)
        if not self.mismatched:
            recorder.passed("python.environment.hash-mismatch")
        for items, severity, which in (
            (self.missing, None, "required"),
            (self.conditional, Severity.LOW, "conditional"),
        ):
            if items:
                note = "environment markers may not apply to the target" if severity else None
                recorder.fail(
                    "python.environment.unresolvable",
                    subject,
                    tool=TOOL,
                    detail={
                        "missing": items[:200],
                        "count": len(items),
                        "kind": which,
                        "note": note,
                    },
                    severity=severity,
                    discriminator=which,
                )
        if not self.missing and not self.conditional:
            recorder.passed("python.environment.unresolvable")
        if len(self.platforms) > 1 or len(self.pythons) > 1:
            recorder.fail(
                "python.environment.platform-mixed",
                subject,
                tool=TOOL,
                detail={"platforms": sorted(self.platforms), "pythonTags": sorted(self.pythons)},
            )
        else:
            recorder.passed("python.environment.platform-mixed")


def _installed(root: ArtifactRef, group: list[UnitClaim], ctx: Context) -> Assembly:
    installed = [c for c in group if c.role == "installed"]
    venv = next((c for c in group if c.role == "venv"), None)
    packages = [(str(c.facts.get("name")), as_str(c.facts.get("rawVersion"))) for c in installed]
    check_allowlist(ctx, "python", packages, _subject(root), canon_name, canon_version)
    listed: list[JSON] = list(sorted(f"{name}=={version}" for name, version in packages)[:1000])
    attributes: dict[str, JSON] = {
        "installed": len(installed),
        "packages": listed,
        "virtualenv": dict(venv.facts) if venv else None,
    }
    bom_refs = {b for c in installed if (b := as_str(c.facts.get("bomRef")))}
    unit = Unit(
        kind=UnitKind.PYTHON_ENVIRONMENT,
        name=f"installed python packages ({root.display})",
        root=root,
        members=_members(group),
        components=tuple(sorted(bom_refs)),
        attributes=attributes,
    )
    return Assembly(unit)
