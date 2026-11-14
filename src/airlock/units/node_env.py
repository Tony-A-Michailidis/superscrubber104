"""Node environments: can the delivery satisfy each lockfile offline?

Each locked package must be present either installed (``node_modules/<path>`` with the locked
version, as ``npm ci`` would lay it out) or as a package tarball whose integrity matches the
lockfile (an offline mirror). A tarball with the right name and version but a different integrity
is a hash mismatch, which is final. Optional packages (often platform-specific) that are missing
are reported at low severity.
"""

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
from airlock.units.facts import as_str, dicts, strings

TOOL = ToolRef("airlock.node-environment", __version__)


def _subject(root: ArtifactRef) -> Subject:
    return Subject(SubjectKind.UNIT, unit=f"{UnitKind.NODE_ENVIRONMENT.value}:{root.display}")


class _Tarballs:
    """Every package tarball in the delivery, by integrity and by name and version."""

    def __init__(self, claims: Iterable[UnitClaim]) -> None:
        self.by_integrity: dict[str, UnitClaim] = {}
        self.by_name: dict[tuple[str, str], list[UnitClaim]] = defaultdict(list)
        for c in claims:
            for value in strings(c.facts.get("integrity")):
                self.by_integrity[value] = c
            self.by_name[(str(c.facts.get("name")), str(c.facts.get("version")))].append(c)


class NodeEnvironmentAssembler:
    name = "node-environment"
    version = "1"
    kind = UnitKind.NODE_ENVIRONMENT

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        tarballs = _Tarballs(c for c in claims if c.role == "tarball")
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for c in claims:
            if c.role in ("lockfile", "installed", "project"):
                groups[c.root].append(c)
        return [
            _Environment(root, group, tarballs, ctx).run() for root, group in sorted(groups.items())
        ]


class _Environment:
    def __init__(
        self, root: ArtifactRef, group: list[UnitClaim], tarballs: _Tarballs, ctx: Context
    ) -> None:
        self.root = root
        self.group = group
        self.tarballs = tarballs
        self.ctx = ctx
        self.members = {c.artifact: UnitMember(c.role, c.artifact, c.sha256) for c in group}
        installed = [c for c in group if c.role == "installed"]
        self.by_path = {str(c.facts.get("path")): c for c in installed}
        self.by_name = {
            (str(c.facts.get("name")), str(c.facts.get("version"))): c for c in installed
        }
        self.lock = next((c for c in group if c.role == "lockfile"), None)
        self.missing: list[dict[str, JSON]] = []
        self.optional_missing: list[dict[str, JSON]] = []
        self.mismatched = 0

    def run(self) -> Assembly:
        locked = dicts(self.lock.facts.get("entries")) if self.lock else []
        entries = [e for e in locked if e.get("version") and not e.get("link")]
        for entry in entries:
            self._resolve(entry)
        if self.lock is not None:
            self._report()
        packages = [(str(e.get("name")), as_str(e.get("version"))) for e in entries]
        packages += [(name, version) for name, version in self.by_name]
        check_allowlist(self.ctx, "npm", packages, _subject(self.root))
        project = next((c for c in self.group if c.role == "project"), None)
        name = (as_str(project.facts.get("name")) if project else None) or "node environment"
        missing: list[JSON] = [f"{m.get('name')}@{m.get('version')}" for m in self.missing]
        optional: list[JSON] = [
            f"{m.get('name')}@{m.get('version')}" for m in self.optional_missing
        ]
        attributes: dict[str, JSON] = {
            "lockfile": name_of(self.lock.artifact) if self.lock else None,
            "format": self.lock.facts.get("format") if self.lock else None,
            "locked": len(entries),
            "installed": len(self.by_path),
            "unresolvable": missing[:200],
            "optionalUnresolvable": optional[:200],
        }
        bom_refs = {b for c in self.group if (b := as_str(c.facts.get("bomRef")))}
        unit = Unit(
            kind=UnitKind.NODE_ENVIRONMENT,
            name=name,
            root=self.root,
            members=tuple(sorted(self.members.values(), key=lambda m: m.artifact)),
            components=tuple(sorted(bom_refs)),
            attributes=attributes,
        )
        return Assembly(unit)

    def _use(self, claim: UnitClaim) -> None:
        self.members[claim.artifact] = UnitMember("tarball", claim.artifact, claim.sha256)

    def _resolve(self, entry: dict[str, JSON]) -> None:
        name, version = str(entry.get("name")), str(entry.get("version"))
        path, integrity = as_str(entry.get("path")), as_str(entry.get("integrity"))
        installed = self.by_path.get(path) if path else self.by_name.get((name, version))
        if installed is not None and str(installed.facts.get("version")) == version:
            return
        exact = self.tarballs.by_integrity.get(integrity) if integrity else None
        if exact is not None:
            self._use(exact)
            return
        candidates = self.tarballs.by_name.get((name, version), [])
        if candidates and integrity:
            algorithm = integrity.split("-", 1)[0]
            comparable = [
                c
                for c in candidates
                if any(v.startswith(f"{algorithm}-") for v in strings(c.facts.get("integrity")))
            ]
            for c in comparable:
                self.mismatched += 1
                self.ctx.recorder.fail(
                    "node.environment.integrity-mismatch",
                    Subject.of_artifact(c.artifact),
                    tool=TOOL,
                    detail={
                        "package": name,
                        "version": version,
                        "locked": integrity,
                        "lockfile": self.lock.artifact.display if self.lock else None,
                    },
                )
            if comparable:
                return
        if candidates:
            self._use(candidates[0])  # no comparable integrity recorded: matched by name
            return
        item: dict[str, JSON] = {"name": name, "version": version, "path": path}
        if installed is not None:
            item["installedVersion"] = installed.facts.get("version")
        (self.optional_missing if entry.get("optional") else self.missing).append(item)

    def _report(self) -> None:
        recorder, subject = self.ctx.recorder, _subject(self.root)
        if not self.mismatched:
            recorder.passed("node.environment.integrity-mismatch")
        for items, severity, which in (
            (self.missing, None, "required"),
            (self.optional_missing, Severity.LOW, "optional"),
        ):
            if items:
                recorder.fail(
                    "node.environment.unresolvable",
                    subject,
                    tool=TOOL,
                    detail={"missing": items[:200], "count": len(items), "kind": which},
                    severity=severity,
                    discriminator=which,
                )
        if not self.missing and not self.optional_missing:
            recorder.passed("node.environment.unresolvable")
