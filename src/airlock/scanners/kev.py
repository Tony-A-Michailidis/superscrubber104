"""CISA Known Exploited Vulnerabilities catalogue: a data feed, not a scanner.

The catalogue is the public JSON file from cisa.gov. It runs nothing; it marks each
vulnerability finding ``kev=true`` or ``kev=false`` so that a policy can treat actively exploited
vulnerabilities differently (``where: {kev: "true"}``). Without it, findings carry
``kev=unknown``. It is pinned and age-checked like any scanner database.
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

from airlock.core.interfaces import Context
from airlock.core.model import Analysis
from airlock.core.policy import PluginPolicy
from airlock.scanners.base import DataInfo, Ready, ScanError, Target

_LIMIT = 64 << 20


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class KevFeed:
    name = "kev"
    capability = "kev"
    rules: tuple[str, ...] = ()
    binary_names: tuple[str, ...] = ()  # data only

    def __init__(self) -> None:
        self.ids: frozenset[str] | None = None  # None: not loaded

    def version(self, ready: Ready) -> str | None:
        return None

    def _load(self, policy: PluginPolicy) -> dict[str, object]:
        if policy.path is None:
            raise ScanError("plugins.kev.path (the catalogue JSON file) is not set")
        if not policy.path.is_file():
            raise ScanError(f"KEV catalogue not found at {policy.path}")
        if policy.path.stat().st_size > _LIMIT:
            raise ScanError("KEV catalogue is larger than airlock will read")
        try:
            data = json.loads(policy.path.read_bytes())
        except (ValueError, UnicodeDecodeError) as exc:
            raise ScanError(f"KEV catalogue is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ScanError("not a KEV catalogue (no vulnerabilities list)")
        return data

    def data(self, policy: PluginPolicy) -> DataInfo:
        try:
            data = self._load(policy)
        except ScanError as exc:
            return DataInfo(problem=str(exc))
        assert policy.path is not None  # noqa: S101
        version = data.get("catalogVersion")
        return DataInfo(
            version=str(version) if version else None,
            built_at=_parse_time(data.get("dateReleased")),
            files=(policy.path.name,),
        )

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        data = self._load(ready.policy)
        entries = data["vulnerabilities"]
        assert isinstance(entries, list)  # noqa: S101 - checked by _load
        self.ids = frozenset(
            str(e["cveID"]).upper() for e in entries if isinstance(e, dict) and e.get("cveID")
        )

    def mark(self, *ids: str) -> str:
        """``true``, ``false``, or ``unknown`` when no catalogue was loaded."""
        if self.ids is None:
            return "unknown"
        return "true" if any(i.upper() in self.ids for i in ids if i) else "false"
