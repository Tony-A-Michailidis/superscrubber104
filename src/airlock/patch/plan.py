"""``airlock patch plan`` and ``confirm``: the patch gap between an inventory and the feeds.

For every advisory in the feeds that applies to the host's OS release, each fix is compared with
what is installed (``rpm`` or ``dpkg`` version ordering). An installed package older than the fix
is a gap. For Windows, a KB is missing when it is neither installed nor superseded by an installed
KB. Each gap carries its CVEs, severity, whether a CVE is on CISA's KEV list, whether it needs a
reboot, and how long ago the advisory was published.

Emergency plans narrow the result to ``--cve`` or ``--kev``. The plan lists exactly which
package versions to fetch; the bundle that carries them goes through pack and verify like any
other, and ``confirm`` against a fresh inventory shows the gap closed.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from airlock.core.model import API_VERSION
from airlock.feeds import Advisory, Feed, Fix
from airlock.formats.deb import deb_vercmp
from airlock.formats.rpm import compare_evr
from airlock.patch.inventory import InstalledPackage, Inventory

# What dnf's needs-restarting -r and Ubuntu's reboot-required treat as needing a reboot.
_REBOOT = frozenset(
    {
        "glibc", "linux-firmware", "systemd", "udev", "openssl-libs", "gnutls", "dbus",
        "dbus-broker", "dbus-daemon", "microcode_ctl", "libc6", "libssl3", "libssl3t64",
        "intel-microcode", "amd64-microcode",
    }
)  # fmt: skip


def needs_reboot(package: str) -> bool:
    return package in _REBOOT or package.startswith(("kernel", "linux-image", "linux-modules"))


_SEVERITY_ORDER = {
    "critical": 0,
    "important": 1,
    "high": 1,
    "moderate": 2,
    "medium": 2,
    "low": 3,
    "negligible": 4,
}


@dataclass(frozen=True, slots=True)
class PackageGap:
    name: str  # the installed package (binary) or KB
    installed: str
    fixed: str
    arch: str = ""


@dataclass(frozen=True, slots=True)
class Gap:
    advisory: str
    title: str
    severity: str
    cves: tuple[str, ...]
    kev: bool
    reboot: bool
    published: datetime | None
    age_days: int | None
    packages: tuple[PackageGap, ...]
    url: str | None = None


@dataclass(frozen=True, slots=True)
class FeedStatus:
    name: str
    kind: str
    built_at: datetime | None
    age_days: int | None
    max_age_days: int | None
    stale: bool
    advisories: int
    problems: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PatchPlan:
    inventory: str  # label
    os: str
    created_at: datetime
    feeds: tuple[FeedStatus, ...]
    gaps: tuple[Gap, ...]
    fetch: tuple[str, ...]  # what to download: name-version.arch, name=version, KBnnnnnnn
    filters: dict[str, str] = field(default_factory=dict)
    api_version: str = API_VERSION
    kind: str = "PatchPlan"

    @property
    def stale_feeds(self) -> list[str]:
        return [f.name for f in self.feeds if f.stale]


def _applies(fix: Fix, inventory: Inventory) -> bool:
    """Whether a fix is for this host's OS release (fixes without an ecosystem always are)."""
    if not fix.ecosystem:
        return True
    os = inventory.os
    if os.family == "windows":
        return fix.ecosystem.lower() == os.name.lower()
    parts = [p.lower() for p in fix.ecosystem.split(":") if p.lower() not in ("pro", "lts")]
    if not parts or parts[0].replace(" ", "") != os.id.lower().replace(" ", ""):
        return False
    if len(parts) < 2:
        return True
    wanted = parts[1]
    return os.version_id == wanted or os.version_id.split(".")[0] == wanted


def _older(installed: str, fixed: str, family: str) -> bool:
    return (compare_evr(installed, fixed) if family == "rpm" else deb_vercmp(installed, fixed)) < 0


def _linux_gaps(
    advisory: Advisory, inventory: Inventory, by_name: Mapping[str, list[InstalledPackage]]
) -> list[PackageGap]:
    gaps = []
    by_source: dict[str, list[InstalledPackage]] = {}
    for package in inventory.packages:
        by_source.setdefault(package.source or package.name, []).append(package)
    seen = set()
    for fix in advisory.fixes:
        if not _applies(fix, inventory):
            continue
        candidates = by_source.get(fix.name, []) if fix.source else by_name.get(fix.name, [])
        if fix.source and fix.binaries:
            candidates = [c for c in candidates if c.name in fix.binaries] or candidates
        for package in candidates:
            if (
                fix.arch
                and package.arch
                and fix.arch not in (package.arch, "noarch", "src")
                and package.arch != "noarch"
            ):
                continue
            key = (package.name, package.arch)
            if key not in seen and _older(package.version, fix.fixed, inventory.os.family):
                seen.add(key)
                gaps.append(PackageGap(package.name, package.version, fix.fixed, package.arch))
    return gaps


def _windows_gaps(advisories: list[Advisory], inventory: Inventory) -> dict[str, list[PackageGap]]:
    installed = {p.name.upper() for p in inventory.packages}
    supersedes = {a.id.upper(): {s.upper() for s in a.supersedes} for a in advisories}
    covered = set(installed)
    frontier = list(installed)
    while frontier:  # an installed update covers everything it supersedes, transitively
        for older in supersedes.get(frontier.pop(), set()):
            if older not in covered:
                covered.add(older)
                frontier.append(older)
    out = {}
    for advisory in advisories:
        if advisory.id.upper() in covered:
            continue
        if any(_applies(f, inventory) for f in advisory.fixes):
            out[advisory.id] = [PackageGap(advisory.id, "", advisory.id)]
    # A missing update superseded by another missing one is not needed: install the newer.
    missing = set(out)
    for advisory in advisories:
        if advisory.id in missing:
            for older in supersedes.get(advisory.id.upper(), set()):
                out.pop(older, None)
    return out


def feed_status(
    feeds: Iterable[Feed], now: datetime, max_age: Mapping[str, timedelta]
) -> list[FeedStatus]:
    statuses = []
    for feed in feeds:
        limit = max_age.get(feed.kind, max_age.get("default"))
        age = (now - feed.built_at) if feed.built_at else None
        stale = bool(feed.problems) or (limit is not None and (age is None or age > limit))
        statuses.append(
            FeedStatus(
                feed.name,
                feed.kind,
                feed.built_at,
                age.days if age is not None else None,
                limit.days if limit is not None else None,
                stale,
                len(feed.advisories),
                tuple(feed.problems),
            )
        )
    return statuses


def plan(
    inventory: Inventory,
    feeds: list[Feed],
    now: datetime,
    *,
    max_age: Mapping[str, timedelta] | None = None,
    cves: Iterable[str] = (),
    kev_only: bool = False,
) -> PatchPlan:
    kev = frozenset().union(*(f.cves for f in feeds if f.kind == "kev"))
    advisories = [a for f in feeds if f.kind != "kev" for a in f.advisories]
    wanted_cves = {c.upper() for c in cves}
    by_name = inventory.installed()
    gaps: list[Gap] = []
    if inventory.os.family == "windows":
        missing = _windows_gaps([a for a in advisories if a.source == "msrc"], inventory)
        found = [(a, missing[a.id]) for a in advisories if a.id in missing]
    else:
        found = [
            (a, g)
            for a in advisories
            if a.source != "msrc" and (g := _linux_gaps(a, inventory, by_name))
        ]
    for advisory, packages in found:
        on_kev = any(c.upper() in kev for c in advisory.cves)
        if wanted_cves and not wanted_cves.intersection(c.upper() for c in advisory.cves):
            continue
        if kev_only and not on_kev:
            continue
        gaps.append(
            Gap(
                advisory=advisory.id,
                title=advisory.title,
                severity=advisory.severity,
                cves=advisory.cves,
                kev=on_kev,
                reboot=advisory.reboot or any(needs_reboot(p.name) for p in packages),
                published=advisory.published,
                age_days=(now - advisory.published).days if advisory.published else None,
                packages=tuple(packages),
                url=advisory.url,
            )
        )
    gaps.sort(key=lambda g: (not g.kev, _SEVERITY_ORDER.get(g.severity, 9), g.advisory))
    fetch = _fetch_list(gaps, inventory.os.family)
    filters = {}
    if wanted_cves:
        filters["cve"] = ",".join(sorted(wanted_cves))
    if kev_only:
        filters["kev"] = "true"
    return PatchPlan(
        inventory=inventory.label,
        os=f"{inventory.os.id} {inventory.os.version_id}".strip(),
        created_at=now,
        feeds=tuple(feed_status(feeds, now, max_age or {})),
        gaps=tuple(gaps),
        fetch=fetch,
        filters=filters,
    )


def _fetch_list(gaps: Iterable[Gap], family: str) -> tuple[str, ...]:
    """The newest fixed version of each package, in the form the package manager takes."""
    newest: dict[tuple[str, str], str] = {}
    for gap in gaps:
        for package in gap.packages:
            key = (package.name, package.arch)
            current = newest.get(key)
            if current is None or (family != "windows" and _older(current, package.fixed, family)):
                newest[key] = package.fixed
    if family == "windows":
        return tuple(sorted(name for name, _ in newest))
    if family == "rpm":
        return tuple(
            sorted(
                f"{n}-{v.split(':', 1)[-1]}.{a}" if a else f"{n}-{v}"
                for (n, a), v in newest.items()
            )
        )
    return tuple(sorted(f"{n}={v}" for (n, _), v in newest.items()))


def confirm(
    previous: PatchPlan, inventory: Inventory, feeds: list[Feed], now: datetime
) -> dict[str, list[str]]:
    """Which gaps of an earlier plan a fresh inventory has closed."""
    current = plan(inventory, feeds, now)
    open_now = {g.advisory for g in current.gaps}
    closed = [g.advisory for g in previous.gaps if g.advisory not in open_now]
    still_open = [g.advisory for g in previous.gaps if g.advisory in open_now]
    new = sorted(open_now - {g.advisory for g in previous.gaps})
    return {"closed": closed, "open": still_open, "new": new}


def _cell(value: object) -> str:
    if value is None or value is False:
        return ""
    return "yes" if value is True else str(value)


def markdown(result: PatchPlan) -> str:
    kev = sum(g.kev for g in result.gaps)
    reboots = sum(g.reboot for g in result.gaps)
    lines = [
        f"# Patch plan: {result.inventory} ({result.os})",
        "",
        f"{len(result.gaps)} advisories to apply, {kev} with a CVE on the KEV list, "
        f"{reboots} needing a reboot.",
        "",
    ]
    if result.filters:
        limits = ", ".join(f"{k}={v}" for k, v in sorted(result.filters.items()))
        lines += [f"Emergency plan, limited to: {limits}.", ""]
    if result.stale_feeds:
        stale = ", ".join(result.stale_feeds)
        lines += [f"**Stale or unreadable feeds:** {stale}. The plan may miss advisories.", ""]
    lines += [
        "| Advisory | Severity | KEV | Reboot | Age (days) | CVEs | Packages |",
        "|---|---|---|---|---|---|---|",
    ]
    for gap in result.gaps:
        packages = ", ".join(f"{p.name} {p.installed} → {p.fixed}".strip() for p in gap.packages)
        cves = ", ".join(gap.cves[:5]) + (" …" if len(gap.cves) > 5 else "")
        cells = [gap.advisory, gap.severity, gap.kev, gap.reboot, gap.age_days, cves, packages]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    lines += [
        "",
        "## Feeds",
        "",
        "| Feed | Kind | Built | Age (days) | Limit | Stale |",
        "|---|---|---|---|---|---|",
    ]
    for feed in result.feeds:
        built = feed.built_at.date().isoformat() if feed.built_at else "unknown"
        cells = [feed.name, feed.kind, built, feed.age_days, feed.max_age_days, feed.stale]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    lines += ["", "## Fetch", "", *(f"- `{item}`" for item in result.fetch), ""]
    return "\n".join(lines)
