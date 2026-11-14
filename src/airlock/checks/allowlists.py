"""Approved-package lists: only packages the site approved may cross.

The lists live in the policy (``allowlists.python``, ``allowlists.npm``), inline or in a pinned
file with one entry per line. An entry is a name, or a name pinned to one version
(``requests==2.32.3``, ``left-pad@1.3.0``). Range entries (``react@^18``) match the name only.
Unlisted packages are a finding: a typo-squatted or hallucinated dependency is exactly a package
nobody approved.
"""

import re
from collections.abc import Callable, Iterable

from airlock.analyzer import TOOL
from airlock.core.interfaces import Context
from airlock.core.model import Severity, Subject
from airlock.core.policy import AllowlistMode


def _entries(ctx: Context, ecosystem: str) -> tuple[list[str], AllowlistMode] | None:
    allowlist = ctx.policy.allowlists.get(ecosystem)
    if allowlist is None:
        return None
    entries = [e for e in allowlist.entries if isinstance(e, str)]
    if allowlist.file is not None:
        text = allowlist.file.path.read_text(encoding="utf-8")
        entries += [line.split("#", 1)[0].strip() for line in text.splitlines()]
    return [e for e in entries if e], allowlist.mode


def _split(entry: str, ecosystem: str) -> tuple[str, str | None]:
    if ecosystem == "npm":
        at = entry.rfind("@")
        name, version = (entry[:at], entry[at + 1 :]) if at > 0 else (entry, None)
    else:
        name, _, version = entry.partition("==")
        name = re.split(r"[<>=!~;\[ ]", name, maxsplit=1)[0]
    exact = version if version and re.fullmatch(r"[\w.+-]+", version) else None
    return name.strip(), exact


def check_allowlist(
    ctx: Context,
    ecosystem: str,
    packages: Iterable[tuple[str, str | None]],
    subject: Subject,
    canon: Callable[[str], str] = str.lower,
    canon_version: Callable[[str], str] = str,
) -> None:
    """Record one finding listing each (name, version) in ``packages`` the policy does not allow."""
    configured = _entries(ctx, ecosystem)
    if configured is None:
        return
    entries, mode = configured
    allowed: dict[str, set[str | None]] = {}
    for entry in entries:
        name, version = _split(entry, ecosystem)
        allowed.setdefault(canon(name), set()).add(canon_version(version) if version else None)
    unapproved = []
    for name, version in sorted(set(packages), key=lambda p: (p[0], p[1] or "")):
        versions = allowed.get(canon(name))
        normalised = canon_version(version) if version else None
        if versions is None or (None not in versions and normalised not in versions):
            unapproved.append({"name": name, "version": version})
    if unapproved:
        ctx.recorder.fail(
            "package.allowlist.unapproved",
            subject,
            tool=TOOL,
            detail={
                "ecosystem": ecosystem,
                "packages": unapproved[:200],
                "count": len(unapproved),
                "mode": mode.value,
            },
            attributes={"ecosystem": ecosystem},
            severity=Severity.INFO if mode is AllowlistMode.REPORT else None,
            discriminator=ecosystem,
        )
    else:
        ctx.recorder.passed("package.allowlist.unapproved")
