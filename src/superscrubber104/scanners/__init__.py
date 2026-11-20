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
    """Top-level files on disk, in the form scanners take.

    Locations are made absolute: a scanner runs in its own private working directory, where a
    path relative to the operator's directory (``inspect delivery``) would name nothing.
    """
    return [Target(f.ref, f.location.absolute(), f.size) for f in files]


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
    failed: dict[str, list[str]] = {}  # capability -> why each configured scanner did not run
    with tempfile.TemporaryDirectory(prefix="superscrubber104-scan-") as scratch:
        for scanner in scanners:
            policy = configured.get(scanner.name)
            if policy is None:
                continue
            workdir = Path(scratch) / scanner.name
            workdir.mkdir()
            status, ready = Preflight(scanner, policy, ctx, workdir).run()
            statuses.append(status)
            if preflight_only:
                continue
            if ready is None:
                why = f"{scanner.name} is configured but failed its pre-flight (see plugin.*)"
                failed.setdefault(scanner.capability, []).append(why)
                continue
            try:
                scanner.scan(ready, targets, analysis, ctx)
            except Exception as exc:
                subject = plugin_subject(scanner.name)
                error = str(exc) if isinstance(exc, ScanError) else f"{type(exc).__name__}: {exc}"
                ctx.recorder.error("plugin.scan.error", subject, tool=ready.tool, error=error)
                why = f"{scanner.name} is configured but failed (see plugin.scan.error)"
                failed.setdefault(scanner.capability, []).append(why)
                continue
            ran.add(scanner.capability)
    for capability, (rules, applies, reason) in CAPABILITIES.items():
        if capability not in ran and not preflight_only and applies(analysis):
            why = "; ".join(failed.get(capability, [])) or reason
            ctx.recorder.not_assessed(rules, Subject.bundle(), tool=TOOL, reason=why)
    return tuple(sorted(statuses, key=lambda s: s.name))
