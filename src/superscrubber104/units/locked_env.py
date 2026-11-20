"""Locked environments for Java, Go, Rust and .NET: can the delivery satisfy each lockfile offline?

The ecosystem handlers make two kinds of claim, with the same facts whatever the ecosystem:

* ``lockfile``: ``requirements``, a list of ``{name, version, hashes, vendored}``. Hashes are
  ``"<algorithm>:<value>"``: ``sha256``/``sha512``/``sha1`` in hex, or Go's ``h1:``.
* ``distribution``: something in the delivery that can satisfy a requirement: ``{name, version,
  hashes, bomRef}``.

Each lockfile becomes a unit. A requirement is resolved by a distribution with the same name and
version; when both sides record a hash with the same algorithm, one must match
(``environment.lock.hash-mismatch``, final: the lockfile travelled with the content). A requirement
nothing satisfies is ``environment.lock.unresolvable``. Vendored requirements (``go mod vendor``,
``cargo vendor`` without a hash) count as resolved.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence

from superscrubber104 import __version__
from superscrubber104.core.canonical import JSON
from superscrubber104.core.interfaces import Assembly, Context
from superscrubber104.core.model import (
    Subject,
    SubjectKind,
    ToolRef,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
)
from superscrubber104.handlers.common import name_of
from superscrubber104.units.facts import as_str, dicts, strings

TOOL = ToolRef("superscrubber104.locked-environment", __version__)
_SAMPLE = 200


def _algorithms(hashes: Iterable[str]) -> set[str]:
    return {h.partition(":")[0] for h in hashes}


class LockedEnvironmentAssembler:
    """One instance per ecosystem's unit kind."""

    version = "1"

    def __init__(self, kind: UnitKind, ecosystem: str) -> None:
        self.kind, self.ecosystem = kind, ecosystem
        self.name = f"{ecosystem}-environment"

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        distributions: dict[tuple[str, str], list[UnitClaim]] = defaultdict(list)
        lockfiles: list[UnitClaim] = []
        for claim in claims:
            if claim.role == "distribution":
                key = (str(claim.facts.get("name")), str(claim.facts.get("version")))
                distributions[key].append(claim)
            elif claim.role == "lockfile":
                lockfiles.append(claim)
        return [
            self._resolve(lock, distributions, ctx)
            for lock in sorted(lockfiles, key=lambda c: c.artifact)
        ]

    def _resolve(
        self,
        lock: UnitClaim,
        distributions: dict[tuple[str, str], list[UnitClaim]],
        ctx: Context,
    ) -> Assembly:
        subject = Subject(SubjectKind.UNIT, unit=f"{self.kind.value}:{lock.root.display}")
        used: list[UnitClaim] = []
        missing: list[JSON] = []
        checked = unverified = vendored = mismatched = 0
        requirements = dicts(lock.facts.get("requirements"))
        for requirement in requirements:
            name, version = str(requirement.get("name")), str(requirement.get("version"))
            if requirement.get("vendored"):
                vendored += 1
                continue
            candidates = distributions.get((name, version), [])
            if not candidates:
                missing.append(f"{name}@{version}")
                continue
            wanted = set(strings(requirement.get("hashes")))
            comparable = [
                d
                for d in candidates
                if _algorithms(strings(d.facts.get("hashes"))) & _algorithms(wanted)
            ]
            if not wanted or not comparable:
                unverified += 1 if wanted else 0
                used.extend(candidates)
                continue
            matching = [d for d in comparable if wanted & set(strings(d.facts.get("hashes")))]
            if matching:
                checked += 1
                used.extend(matching)
                continue
            for d in comparable:
                mismatched += 1
                ctx.recorder.fail(
                    "environment.lock.hash-mismatch",
                    Subject.of_artifact(d.artifact),
                    tool=TOOL,
                    detail={
                        "ecosystem": self.ecosystem,
                        "requirement": f"{name}@{version}",
                        "lockfile": lock.artifact.display,
                        "locked": sorted(wanted)[:10],
                        "actual": strings(d.facts.get("hashes"))[:10],
                    },
                    attributes={"ecosystem": self.ecosystem},
                )
        if not mismatched and checked:
            ctx.recorder.passed("environment.lock.hash-mismatch", checked)
        if missing:
            ctx.recorder.fail(
                "environment.lock.unresolvable",
                subject,
                tool=TOOL,
                detail={
                    "ecosystem": self.ecosystem,
                    "count": len(missing),
                    "missing": missing[:_SAMPLE],
                },
                attributes={"ecosystem": self.ecosystem},
            )
        elif requirements:
            ctx.recorder.passed("environment.lock.unresolvable")
        attributes: dict[str, JSON] = {
            "ecosystem": self.ecosystem,
            "lockfile": name_of(lock.artifact),
            "format": lock.facts.get("format"),
            "requirements": len(requirements),
            "resolved": len(requirements) - len(missing),
            "vendored": vendored,
            "hashChecked": checked,
            "hashUnverifiable": unverified,
            "unresolvable": missing[:_SAMPLE],
        }
        members = {(lock.artifact, "lockfile"): lock.sha256}
        members |= {(d.artifact, "distribution"): d.sha256 for d in used}
        bom_refs = sorted({b for d in used if (b := as_str(d.facts.get("bomRef")))})
        unit = Unit(
            kind=self.kind,
            name=f"{self.ecosystem} environment ({name_of(lock.artifact)})",
            root=lock.root,
            members=tuple(
                UnitMember(role, ref, sha) for (ref, role), sha in sorted(members.items())
            ),
            components=tuple(bom_refs),
            attributes=attributes,
        )
        return Assembly(unit)
