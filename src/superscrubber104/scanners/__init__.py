"""Optional external scanners (malware, vulnerabilities) and the feeds they use.

superscrubber104 works with no scanner at all. A scanner runs only when the policy configures it
under ``plugins``; whatever is not configured, or cannot be trusted, is recorded as *not assessed*
for the whole delivery so that the gap is visible in the evidence, never silent. See
``docs/scanners.md`` for setting them up.
"""

import tempfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Analysis, PluginStatus, Subject
from superscrubber104.scanners.authenticode import Authenticode, has_windows_packages
from superscrubber104.scanners.base import (
    TOOL,
    Preflight,
    ScanError,
    Scanner,
    Target,
    plugin_subject,
)
from superscrubber104.scanners.clamav import ClamAV
from superscrubber104.scanners.kev import KevFeed
from superscrubber104.scanners.qemu_img import QemuImg, has_disk_images
from superscrubber104.scanners.sast import Bandit, Semgrep, has_source
from superscrubber104.scanners.trivy import Trivy
from superscrubber104.walker import FileView

__all__ = ["Target", "default_scanners", "run_scanners", "targets"]

# What each capability checks, when it applies, and how to fill the gap when nothing provides it.
CAPABILITIES: dict[str, tuple[tuple[str, ...], Callable[[Analysis], bool], str]] = {
    "malware": (
        ("malware.detected",),
        lambda _: True,
        "no malware scanner is configured (plugins.clamav)",
    ),
    "vulnerabilities": (
        ("vuln.component.known",),
        lambda _: True,
        "no vulnerability scanner is configured (plugins.trivy)",
    ),
    "sast": (
        ("sast.finding",),
        has_source,
        "no static analysis scanner is configured (plugins.semgrep or plugins.bandit)",
    ),
    "authenticode": (
        (
            "authenticode.signature.invalid",
            "authenticode.signature.untrusted",
            "authenticode.signature.missing",
        ),
        has_windows_packages,
        "no Authenticode verifier is configured (plugins.osslsigncode)",
    ),
    "vm-images": (
        ("vm.image.check",),
        has_disk_images,
        "qemu-img is not configured (plugins.qemu-img); disk headers were read by superscrubber104 "
        "only",
    ),
}


def targets(files: Iterable[FileView]) -> list[Target]:
    """Top-level files on disk, in the form scanners take."""
    return [Target(f.ref, f.location, f.size) for f in files]


def default_scanners() -> tuple[Scanner, ...]:
    """In run order: the KEV feed first, so vulnerability findings can be marked."""
    kev = KevFeed()
    return (kev, ClamAV(), Trivy(kev), Semgrep(), Bandit(), QemuImg(), Authenticode())


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
    and its database dated, which is what ``superscrubber104 plugins check`` reports.
    """
    scanners = tuple(scanners) if scanners is not None else default_scanners()
    configured = ctx.policy.plugins
    known = {s.name for s in scanners}
    statuses: list[PluginStatus] = []
    for name in sorted(set(configured) - known):
        reason = "superscrubber104 has no plugin of this name"
        statuses.append(PluginStatus(name, present=False, reason=reason))
        if configured[name].required:
            ctx.recorder.fail(
                "plugin.required.missing",
                plugin_subject(name),
                tool=TOOL,
                detail={"reason": reason},
            )
    ran: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="superscrubber104-scan-") as scratch:
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
    for capability, (rules, applies, reason) in CAPABILITIES.items():
        if capability not in ran and not preflight_only and applies(analysis):
            ctx.recorder.not_assessed(rules, Subject.bundle(), tool=TOOL, reason=reason)
    return tuple(sorted(statuses, key=lambda s: s.name))
