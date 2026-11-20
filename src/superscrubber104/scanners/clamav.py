"""ClamAV (``clamscan``): malware and heuristic detections.

superscrubber104 always passes the signature directory from the policy, so the scan uses exactly the
databases that were pinned, never whatever the host's own ``freshclam`` last fetched. The age of
the signatures is read from the CVD/CLD headers, which record when Cisco Talos built them.

ClamAV looks inside archives itself. Files over its size ceiling, and archives that exceed its
recursion or file-count limits, are reported by ClamAV as ``Heuristics.Limits.Exceeded``;
superscrubber104 records those as not assessed rather than clean.
"""

import os
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import Analysis, Subject
from superscrubber104.core.policy import PluginPolicy
from superscrubber104.scanners.base import DataInfo, Ready, ScanError, Target, files_under

# Every file type clamscan loads from a database directory (signatures, allow lists, YARA).
SIGNATURE_SUFFIXES = frozenset(
    {
        ".cvd", ".cld", ".cud", ".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb", ".mdu", ".msu",
        ".ndb", ".ndu", ".ldb", ".ldu", ".idb", ".cdb", ".cbc", ".pdb", ".gdb", ".wdb", ".ftm",
        ".fp", ".sfp", ".ign", ".ign2", ".info", ".yar", ".yara", ".crb", ".cat", ".pwdb", ".imp",
    }
)  # fmt: skip
MAX_SIZE = 4000 << 20  # clamscan's ceiling for --max-filesize and --max-scansize
_LINE = re.compile(r"^(?P<path>.+): (?:(?P<signature>\S.*?) )?(?P<status>FOUND|OK|ERROR)$")
_LIMITS = "Heuristics.Limits.Exceeded"


def _header(path: Path) -> tuple[str, str, datetime | None] | None:
    """(database, version, build time) from a CVD/CLD header, or None if it has none."""
    with path.open("rb") as stream:
        head = stream.read(512).decode("ascii", "replace")
    if not head.startswith("ClamAV-VDB:"):
        return None
    fields = head.rstrip("\x00 ").split(":")
    if len(fields) < 9:
        return None
    built: datetime | None = None
    try:
        built = datetime.fromtimestamp(int(fields[8].strip()), UTC)
    except (ValueError, OverflowError, OSError):
        built = None
    return path.stem, fields[2], built


def _key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


class ClamAV:
    name = "clamav"
    capability = "malware"
    rules: tuple[str, ...] = ("malware.detected",)
    binary_names: tuple[str, ...] = ("clamscan",)

    def version(self, ready: Ready) -> str | None:
        out = ready.run(["--version"]).stdout
        match = re.search(r"ClamAV\s+(\d[\w.]*)", out)
        return match.group(1) if match else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        database = policy.database
        if database is None:
            return DataInfo(
                problem="plugins.clamav.database is not set; superscrubber104 does not use the "
                "host's "
                "default signature directory"
            )
        files = files_under(database, lambda p: p.suffix.lower() in SIGNATURE_SUFFIXES)
        if not files:
            return DataInfo(problem=f"no signature files in {database}")
        headers = [h for f in files if (h := _header(database / f)) is not None]
        version = ", ".join(f"{name} {v}" for name, v, _ in sorted(headers)) or None
        dates = [built for _, _, built in headers if built is not None]
        return DataInfo(version=version, built_at=max(dates) if dates else None, files=files)

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        recorder = ctx.recorder
        too_large = [t for t in targets if t.size > MAX_SIZE]
        for target in too_large:
            recorder.not_assessed(
                self.rules,
                Subject.of_artifact(target.ref),
                tool=ready.tool,
                reason="larger than ClamAV can scan (4000 MiB)",
            )
        scanned = [t for t in targets if t.size <= MAX_SIZE]
        if not scanned:
            return
        listing = ready.workdir / "clamscan-files.txt"
        listing.write_text("".join(f"{t.location}\n" for t in scanned), encoding="utf-8")
        assert ready.policy.database is not None  # noqa: S101 - checked by data()
        completed = ready.run(
            [
                f"--database={ready.policy.database}",
                "--no-summary",
                "--stdout",
                "--max-filesize=4000M",
                "--max-scansize=4000M",
                "--alert-exceeds-max=yes",
                f"--file-list={listing}",
                *ready.policy.args,
            ],
            ok=(0, 1),  # 1: something was found
        )
        results: dict[str, list[tuple[str, str | None]]] = {}
        for line in completed.stdout.splitlines():
            match = _LINE.match(line.strip())
            if match:
                results.setdefault(_key(match["path"]), []).append(
                    (match["status"], match["signature"])
                )
        if not results:
            raise ScanError("clamscan produced no results")
        clean = 0
        for target in scanned:
            outcome = results.get(_key(str(target.location)))
            subject = Subject.of_artifact(target.ref)
            if not outcome:
                recorder.not_assessed(
                    self.rules, subject, tool=ready.tool, reason="clamscan did not report on it"
                )
                continue
            found = [sig for status, sig in outcome if status == "FOUND" and sig]
            limits = [sig for sig in found if sig.startswith(_LIMITS)]
            detections = [sig for sig in found if not sig.startswith(_LIMITS)]
            for signature in detections:
                recorder.fail(
                    "malware.detected",
                    subject,
                    tool=ready.tool,
                    detail={"signature": signature},
                    attributes={"signature": signature, "scanner": self.name},
                    discriminator=signature,
                )
            if detections:
                continue
            if limits or any(status == "ERROR" for status, _ in outcome):
                reason = (
                    f"ClamAV stopped at one of its limits ({limits[0]})"
                    if limits
                    else "clamscan could not read it"
                )
                recorder.not_assessed(self.rules, subject, tool=ready.tool, reason=reason)
                continue
            clean += 1
        recorder.passed("malware.detected", clean)
