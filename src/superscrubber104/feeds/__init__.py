"""Security advisory feeds, read from offline snapshots into one shape.

* **OSV** (``osv.py``): one JSON record per advisory, or a directory or zip of them. Covers
  AlmaLinux (ALSA), Ubuntu (USN), Debian, Rocky and the language ecosystems.
* **dnf ``updateinfo.xml``** (``updateinfo.py``): the errata a dnf repository carries, reached
  through the same signed ``repomd.xml`` as its packages (doc 28).
* **Microsoft CVRF** (``cvrf.py``): the monthly security update guide, as the MSRC API returns it
  in JSON, with KB supersedence.
* **CISA KEV** (``kev.py``): which CVEs are known to be exploited.

Every feed records when it was built, so that ``freshness.feeds`` can refuse a stale one.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Fix:
    """A package version (or Windows KB) that fixes the advisory."""

    name: str  # binary package, source package (``source=True``) or KB number
    fixed: str  # the first fixed version ("" for a KB)
    ecosystem: str = ""  # OSV ecosystem ("AlmaLinux:9", "Ubuntu:24.04:LTS"), product for Windows
    arch: str | None = None
    source: bool = False  # name is a source package (Ubuntu's OSV)
    binaries: tuple[str, ...] = ()  # binary packages built from that source


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    source: str  # osv, updateinfo, msrc
    title: str = ""
    severity: str = "unknown"
    published: datetime | None = None
    cves: tuple[str, ...] = ()
    fixes: tuple[Fix, ...] = ()
    reboot: bool = False
    url: str | None = None
    supersedes: tuple[str, ...] = ()  # KB numbers this update replaces (Windows)


@dataclass(slots=True)
class Feed:
    """One feed snapshot as read from disk."""

    name: str
    kind: str  # osv, updateinfo, msrc, kev
    built_at: datetime | None
    advisories: list[Advisory] = field(default_factory=list)
    cves: frozenset[str] = frozenset()  # KEV only
    problems: list[str] = field(default_factory=list)


_SEVERITIES = ("critical", "important", "high", "moderate", "medium", "low", "negligible")


def severity_from(text: str | None) -> str:
    """The severity a title starts with ("Moderate: openssl update" is moderate)."""
    head = (text or "").split(":", 1)[0].strip().lower()
    return head if head in _SEVERITIES else "unknown"
