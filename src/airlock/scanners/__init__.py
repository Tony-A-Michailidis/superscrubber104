"""Optional external scanners (malware, vulnerabilities) and the feeds they use.

airlock works with no scanner at all. A scanner runs only when the policy configures it under
``plugins``; whatever is not configured, or cannot be trusted, is recorded as *not assessed* for
the whole delivery so that the gap is visible in the evidence, never silent. See
``docs/scanners.md`` for setting them up.
"""

import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from airlock.core.interfaces import Context
from airlock.core.model import Analysis, PluginStatus, Subject
from airlock.scanners.base import (
    TOOL,
    Preflight,
    ScanError,
    Scanner,
    Target,
    plugin_subject,
)
from airlock.scanners.clamav import ClamAV
from airlock.scanners.kev import KevFeed
from airlock.scanners.trivy import Trivy
from airlock.walker import FileView

__all__ = ["Target", "default_scanners", "run_scanners", "targets"]

# What each capability checks, and how to fill the gap when nothing provides it.
CAPABILITIES = {
    "malware": (("malware.detected",), "no malware scanner is configured (plugins.clamav)"),
    "vulnerabilities": (
        ("vuln.component.known",),
        "no vulnerability scanner is configured (plugins.trivy)",
    ),
}


def targets(files: Iterable[FileView]) -> list[Target]:
    """Top-level files on disk, in the form scanners take."""
    return [Target(f.ref, f.location, f.size) for f in files]


def default_scanners() -> tuple[Scanner, ...]:
    """In run order: the KEV feed first, so vulnerability findings can be marked."""
    kev = KevFeed()
    return (kev, ClamAV(), Trivy(kev))


def run_scanners(
    ctx: Context,
    targets: Sequence[Target],
    analysis: Analysis,
    scanners: Sequence[Scanner] | None = None,
    *,
    preflight_only: bool = False,
) -> tuple[PluginStatus, ...]:
    """Run every configured scanner over the delivery's top-level files.

    With ``preflight_only`` nothing is scanned: each scanner is found, hashed, version-checked
    and its database dated, which is what ``airlock plugins check`` reports.
    """
    scanners = tuple(scanners) if scanners is not None else default_scanners()
    configured = ctx.policy.plugins
    known = {s.name for s in scanners}
    statuses: list[PluginStatus] = []
    for name in sorted(set(configured) - known):
        reason = "airlock has no plugin of this name"
        statuses.append(PluginStatus(name, present=False, reason=reason))
        if configured[name].required:
            ctx.recorder.fail(
                "plugin.required.missing",
                plugin_subject(name),
                tool=TOOL,
                detail={"reason": reason},
            )
    ran: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="airlock-scan-") as scratch:
        for scanner in scanners:
            policy = configured.get(scanner.name)
            if policy is None:
                continue
            workdir = Path(scratch) / scanner.name
            workdir.mkdir()
            status, ready = Preflight(scanner, policy, ctx, workdir).run()
            statuses.append(status)
            if ready is None or preflight_only:
                continue
            try:
                scanner.scan(ready, targets, analysis, ctx)
            except ScanError as exc:
                subject = plugin_subject(scanner.name)
                ctx.recorder.error("plugin.scan.error", subject, tool=ready.tool, error=str(exc))
                continue
            ran.add(scanner.capability)
    for capability, (rules, reason) in CAPABILITIES.items():
        if capability not in ran and not preflight_only:
            ctx.recorder.not_assessed(rules, Subject.bundle(), tool=TOOL, reason=reason)
    return tuple(sorted(statuses, key=lambda s: s.name))
