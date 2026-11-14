"""Dataset units: a dataset card or ``save_to_disk`` metadata and the data files under it.

A unit forms around a directory holding a dataset card, ``state.json``, ``dataset_info.json``,
``dataset_dict.json`` or a loading script. Data files in that directory or below belong to it.
Data files with no such anchor are still inventoried, with their format and row count, but form
no unit: nothing says they are a dataset rather than application data.

Completeness: every file a ``state.json`` lists, every split a ``dataset_dict.json`` names, and
every ``data_files`` pattern of a card's ``configs`` must be present. The card's licence (or
``dataset_info.json``'s) is evaluated against the licence policy.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from fnmatch import fnmatchcase

from airlock import __version__
from airlock.checks.licences import check_licences
from airlock.core.canonical import JSON, jsonable
from airlock.core.interfaces import Assembly, Context
from airlock.core.model import (
    ArtifactRef,
    Component,
    ComponentType,
    LicenseRef,
    Subject,
    SubjectKind,
    ToolRef,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
)
from airlock.handlers.common import full_path, name_of, parent_of, relative_to
from airlock.licences import Declared, normalise_identifier
from airlock.units.facts import as_dict, as_list, as_str, opt_int, strings

TOOL = ToolRef("airlock.dataset", __version__)
_ANCHORS = frozenset({"card", "state", "info", "dict", "loading-script"})


def _ancestors(ref: ArtifactRef) -> Iterable[ArtifactRef]:
    """``ref`` and every directory (or archive) above it, up to the bundle root."""
    while True:
        yield ref
        parent = parent_of(ref)
        if parent == ref:
            return
        ref = parent


def _relative(ref: ArtifactRef, root: ArtifactRef) -> str:
    return relative_to(ref, root) or name_of(ref)


class DatasetAssembler:
    name = "dataset"
    version = __version__
    kind = UnitKind.DATASET

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for c in claims:
            groups[c.root].append(c)
        anchors = {root for root, cs in groups.items() if any(c.role in _ANCHORS for c in cs)}
        members: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
        for root, cs in groups.items():
            # The outermost anchor owns everything below it: a DatasetDict's splits, a card's
            # data directory.
            owners = [a for a in _ancestors(root) if a in anchors]
            if owners:
                members[owners[-1]].extend(cs)
        for root in sorted(members):
            yield self._unit(root, members[root], ctx)

    def _unit(self, root: ArtifactRef, claims: list[UnitClaim], ctx: Context) -> Assembly:
        unit_id = f"{UnitKind.DATASET.value}:{root.display}"
        subject = Subject(SubjectKind.UNIT, unit=unit_id)
        by_role: dict[str, list[UnitClaim]] = defaultdict(list)
        for c in claims:
            by_role[c.role].append(c)
        data = by_role["data"]
        relative = {_relative(c.artifact, root): c for c in data}
        missing: list[dict[str, JSON]] = []

        for state in by_role["state"]:
            directory = _relative(state.artifact, root).rpartition("/")[0]
            for name in strings(state.facts.get("dataFiles")):
                path = f"{directory}/{name}" if directory else name
                if path not in relative:
                    missing.append({"file": path, "listedIn": _relative(state.artifact, root)})
        states = {_relative(c.artifact, root).rpartition("/")[0] for c in by_role["state"]}
        for record in by_role["dict"]:
            for split in strings(record.facts.get("splits")):
                if split not in states:
                    missing.append({"split": split, "listedIn": "dataset_dict.json"})
        for card_claim in by_role["card"]:
            for config in as_list(card_claim.facts.get("configs")):
                for pattern in strings(as_dict(config).get("dataFiles")):
                    if not any(fnmatchcase(p, pattern) for p in relative):
                        missing.append(
                            {"pattern": pattern, "config": as_str(as_dict(config).get("name"))}
                        )
        if missing:
            ctx.recorder.fail(
                "dataset.file-missing", subject, tool=TOOL, detail={"missing": missing[:100]}
            )
        else:
            ctx.recorder.passed("dataset.file-missing")

        card: Mapping[str, JSON] = by_role["card"][0].facts if by_role["card"] else {}
        info: Mapping[str, JSON] = by_role["info"][0].facts if by_role["info"] else {}
        licence = self._licence(card, info, subject, ctx) if card or info else None
        rows = [opt_int(c.facts.get("rows")) for c in data]
        name = as_str(card.get("prettyName")) or (name_of(root) if root.path != "." else "dataset")
        scripts: list[JSON] = [_relative(c.artifact, root) for c in by_role["loading-script"]]
        attributes: dict[str, JSON] = {
            "files": len(data),
            "formats": jsonable(sorted({str(c.facts.get("format")) for c in data})),
            "rows": sum(r for r in rows if r is not None) if rows and None not in rows else None,
            "splits": jsonable(info.get("splits")),
            "features": jsonable(info.get("features")),
            "licence": licence,
            "loadingScript": scripts,
            "gated": bool(card.get("gated")),
        }
        unit_members = tuple(
            sorted({UnitMember(c.role, c.artifact, c.sha256) for c in claims}, key=_member_key)
        )
        bom_ref = f"dataset:{full_path(root) or '.'}"
        component = Component(
            bom_ref=bom_ref,
            type=ComponentType.DATA,
            name=name,
            licenses=(LicenseRef(expression=licence),) if licence else (),
            evidence=tuple(m.artifact for m in unit_members),
        )
        unit = Unit(
            kind=UnitKind.DATASET,
            name=name,
            root=root,
            members=unit_members,
            components=(bom_ref,),
            attributes={k: v for k, v in attributes.items() if v not in (None, [], {})},
        )
        return Assembly(unit, (component,))

    def _licence(
        self, card: Mapping[str, JSON], info: Mapping[str, JSON], subject: Subject, ctx: Context
    ) -> str | None:
        declared: list[Declared] = []
        for source, facts in (("dataset-card", card), ("dataset-info", info)):
            value = facts.get("license")
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str) and item:
                    name = as_str(facts.get("licenseName"))
                    declared.append(Declared(source, normalise_identifier(item, name), item))
        return check_licences(subject, declared, ctx)


def _member_key(member: UnitMember) -> tuple[str, str]:
    return (member.artifact.display, member.role)
