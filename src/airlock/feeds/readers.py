"""Readers for each feed format, and ``load_feed`` to pick one by content."""

import gzip
import io
import json
import lzma
import re
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, cast

from airlock.archive import ARCHIVE_ERRORS, capped
from airlock.feeds import Advisory, Feed, Fix, severity_from

_LIMIT = 512 << 20
_EXPANDED_LIMIT = 4 << 30
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", text):
        text = text.replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _read(path: Path) -> bytes:
    if path.stat().st_size > _LIMIT:
        raise ValueError(f"{path.name} is larger than airlock will read")
    with path.open("rb") as raw:
        if path.name.endswith(".gz"):
            return capped(cast(IO[bytes], gzip.GzipFile(fileobj=raw)), _EXPANDED_LIMIT).read()
        if path.name.endswith(".xz"):
            return capped(cast(IO[bytes], lzma.LZMAFile(raw)), _EXPANDED_LIMIT).read()
        return raw.read()


# --- OSV ----------------------------------------------------------------------------------------


def osv_advisory(record: dict[str, Any]) -> Advisory:
    fixes = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = str(package.get("ecosystem", ""))
        name = str(package.get("name", ""))
        purl = str(package.get("purl", ""))
        source = "arch=source" in purl or ecosystem.lower().startswith(("ubuntu", "debian"))
        binaries = tuple(
            str(b.get("binary_name"))
            for b in (affected.get("ecosystem_specific") or {}).get("binaries") or []
            if isinstance(b, dict) and b.get("binary_name")
        )
        for range_ in affected.get("ranges") or []:
            if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in range_.get("events") or []:
                if "fixed" in event:
                    fixes.append(
                        Fix(name, str(event["fixed"]), ecosystem, source=source, binaries=binaries)
                    )
    cves = {
        str(a)
        for a in [
            *record.get("upstream", []),
            *record.get("aliases", []),
            *record.get("related", []),
        ]
        if _CVE.match(str(a))
    }
    if _CVE.match(str(record.get("id", ""))):
        cves.add(str(record["id"]))
    severity = severity_from(record.get("summary"))
    if severity == "unknown":
        severity = str((record.get("database_specific") or {}).get("severity", "unknown")).lower()
    url = next(
        (r.get("url") for r in record.get("references") or [] if r.get("type") == "ADVISORY"), None
    )
    return Advisory(
        id=str(record.get("id")),
        source="osv",
        title=str(record.get("summary", "")),
        severity=severity,
        published=_time(record.get("published")),
        cves=tuple(sorted(cves)),
        fixes=tuple(fixes),
        reboot=False,  # decided from the packages a host actually updates (patch.plan)
        url=url,
    )


def _osv_records(path: Path) -> Iterator[dict[str, Any]]:
    if path.is_dir():
        for child in sorted(path.rglob("*.json")):
            yield json.loads(child.read_bytes())
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.filename.endswith(".json") and info.file_size < 16 << 20:
                    yield json.loads(archive.read(info))
    else:
        document = json.loads(_read(path))
        if isinstance(document, list):
            yield from document
        elif isinstance(document, dict) and isinstance(document.get("vulns"), list):
            yield from document["vulns"]
        else:
            yield document


def read_osv(path: Path) -> Feed:
    advisories = []
    newest = None
    for record in _osv_records(path):
        if isinstance(record, dict) and record.get("id"):
            advisory = osv_advisory(record)
            advisories.append(advisory)
            modified = _time(record.get("modified"))
            if modified and (newest is None or modified > newest):
                newest = modified
    return Feed(path.name, "osv", newest, advisories)


# --- dnf updateinfo -----------------------------------------------------------------------------


def read_updateinfo(path: Path) -> Feed:
    advisories = []
    newest = None
    data = _read(path)
    for _, element in ET.iterparse(io.BytesIO(data), events=("end",)):  # noqa: S314
        if element.tag != "update":
            continue
        if element.get("type") != "security":
            element.clear()
            continue
        issued = element.find("issued")
        updated = element.find("updated")
        published = _time(issued.get("date") if issued is not None else None)
        changed = _time(updated.get("date") if updated is not None else None) or published
        if changed and (newest is None or changed > newest):
            newest = changed
        cves = sorted(
            {
                r.get("id", "")
                for r in element.iter("reference")
                if r.get("type") == "cve" and _CVE.match(r.get("id", ""))
            }
        )
        fixes = []
        reboot = False
        for package in element.iter("package"):
            epoch = package.get("epoch", "0")
            prefix = f"{epoch}:" if epoch not in ("", "0") else ""
            evr = f"{prefix}{package.get('version')}-{package.get('release')}"
            fixes.append(Fix(package.get("name", ""), evr, arch=package.get("arch")))
            reboot |= (package.findtext("reboot_suggested") or "").strip().lower() in ("true", "1")
        advisories.append(
            Advisory(
                id=element.findtext("id") or "",
                source="updateinfo",
                title=element.findtext("title") or "",
                severity=(
                    element.findtext("severity") or severity_from(element.findtext("title"))
                ).lower(),
                published=published,
                cves=tuple(cves),
                fixes=tuple(fixes),
                reboot=reboot,
            )
        )
        element.clear()
    return Feed(path.name, "updateinfo", newest, advisories)


# --- Microsoft CVRF -----------------------------------------------------------------------------


def read_cvrf(path: Path) -> Feed:
    document = json.loads(_read(path))
    products = {
        p.get("ProductID"): p.get("Value", "")
        for p in (document.get("ProductTree") or {}).get("FullProductName") or []
    }
    tracking = document.get("DocumentTracking") or {}
    built = _time(tracking.get("CurrentReleaseDate"))
    by_kb: dict[str, dict[str, Any]] = {}
    for vulnerability in document.get("Vulnerability") or []:
        cve = str(vulnerability.get("CVE", ""))
        severity = "unknown"
        for threat in vulnerability.get("Threats") or []:
            if threat.get("Type") == 3:  # severity
                severity = str((threat.get("Description") or {}).get("Value", severity)).lower()
                break
        for remediation in vulnerability.get("Remediations") or []:
            kb = str((remediation.get("Description") or {}).get("Value", ""))
            if remediation.get("Type") != 2 or not kb.isdigit():  # 2: vendor fix
                continue
            entry = by_kb.setdefault(
                kb,
                {
                    "cves": set(),
                    "products": set(),
                    "supersedes": set(),
                    "severity": [],
                    "reboot": False,
                    "url": remediation.get("URL"),
                },
            )
            entry["cves"].add(cve)
            entry["products"] |= {products.get(p, p) for p in remediation.get("ProductID") or []}
            for old in re.findall(r"\d{6,8}", str(remediation.get("Supercedence") or "")):
                entry["supersedes"].add(f"KB{old}")
            entry["severity"].append(severity)
            entry["reboot"] |= (
                str((remediation.get("RestartRequired") or {}).get("Value", "")).lower() == "yes"
            )
    advisories = []
    document_id = (tracking.get("Identification") or {}).get("ID", {}).get("Value", "MSRC")
    order = ("critical", "important", "moderate", "low")
    for kb, entry in sorted(by_kb.items()):
        severity = next((s for s in order if s in entry["severity"]), "unknown")
        fixes = tuple(Fix(f"KB{kb}", "", product) for product in sorted(entry["products"]))
        advisories.append(
            Advisory(
                id=f"KB{kb}",
                source="msrc",
                title=f"{document_id} KB{kb}",
                severity=severity,
                published=built,
                cves=tuple(sorted(c for c in entry["cves"] if c)),
                fixes=fixes,
                reboot=bool(entry["reboot"]),
                url=entry["url"],
                supersedes=tuple(sorted(entry["supersedes"])),
            )
        )
    return Feed(path.name, "msrc", built, advisories)


# --- KEV ----------------------------------------------------------------------------------------


def read_kev(path: Path) -> Feed:
    document = json.loads(_read(path))
    cves = frozenset(
        str(e["cveID"]).upper()
        for e in document.get("vulnerabilities") or []
        if isinstance(e, dict) and e.get("cveID")
    )
    return Feed(path.name, "kev", _time(document.get("dateReleased")), cves=cves)


# --- detection ----------------------------------------------------------------------------------


def load_feed(path: Path) -> Feed:
    """Read a feed snapshot, choosing the reader from its content."""
    if path.is_dir() or path.suffix == ".zip":
        return read_osv(path)
    head = _read(path)[:4096].lstrip()
    if head.startswith(b"<"):
        return read_updateinfo(path)
    text = head.decode("utf-8", "replace")
    if '"catalogVersion"' in text or ('"vulnerabilities"' in text and '"cveID"' in text):
        return read_kev(path)
    if '"DocumentTracking"' in text or '"ProductTree"' in text or '"DocumentTitle"' in text:
        return read_cvrf(path)
    return read_osv(path)


def load_feeds(paths: Iterable[Path]) -> list[Feed]:
    feeds = []
    for path in paths:
        try:
            feeds.append(load_feed(path))
        except (*ARCHIVE_ERRORS, ET.ParseError, KeyError, TypeError, AttributeError) as exc:
            feeds.append(Feed(path.name, "unknown", None, problems=[f"unreadable: {exc}"]))
    return feeds
