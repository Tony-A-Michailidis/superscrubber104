"""``superscrubber104 patch inventory``: what is installed on a high-side host, signed, to cross
outbound.

Read statically from a root filesystem (the host's ``/``, a mounted image, a container export):
``etc/os-release``, the RPM database (``rpmdb.sqlite``) or dpkg's ``status``. Hosts whose
database cannot be read that way (AlmaLinux 8 and older keep it in Berkeley DB) give a package
listing from ``rpm -qa`` or ``dpkg-query`` instead. Windows hosts are inventoried from what
PowerShell reports (``Get-HotFix`` and the OS build, see doc 33), since superscrubber104 runs on
Linux.

The inventory holds package names, versions, architectures and source packages, the OS identity,
and GPU driver and CUDA versions if present. Nothing else: no host name (the operator gives a
label), no paths, no users, no configuration. It is the only thing that crosses high-to-low, so
its schema is the leak boundary.
"""

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from superscrubber104 import bundle as layout
from superscrubber104.core.errors import ConfigError
from superscrubber104.core.model import API_VERSION
from superscrubber104.core.serde import from_data
from superscrubber104.core.signing import Envelope, Signer, VerifyKey, sign_envelope
from superscrubber104.formats.deb import parse_fields
from superscrubber104.formats.rpm import RPMError, identity, read_header_blob

PAYLOAD_TYPE = "application/vnd.superscrubber104.inventory+json"
_RPMDBS = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
_LABEL = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True, slots=True)
class InstalledPackage:
    name: str
    version: str  # rpm: [epoch:]version-release; deb: the Debian version; KB: ""
    arch: str = ""
    source: str | None = None  # deb: the source package, when it differs from the name


@dataclass(frozen=True, slots=True)
class OsIdentity:
    family: str  # rpm, deb, windows
    id: str  # almalinux, ubuntu, windows
    version_id: str  # 9.4, 24.04, 10.0.20348.2700
    name: str = ""  # PRETTY_NAME or the Windows product name


@dataclass(frozen=True, slots=True)
class Inventory:
    label: str
    collected_at: datetime
    os: OsIdentity
    packages: tuple[InstalledPackage, ...] = ()
    components: dict[str, str] = field(default_factory=dict)  # nvidiaDriver, cuda
    api_version: str = API_VERSION
    kind: str = "Inventory"

    def installed(self) -> dict[str, list[InstalledPackage]]:
        out: dict[str, list[InstalledPackage]] = {}
        for package in self.packages:
            out.setdefault(package.name, []).append(package)
        return out


def _os_release(root: Path) -> dict[str, str]:
    for candidate in ("etc/os-release", "usr/lib/os-release"):
        path = root / candidate
        if path.is_file():
            fields = {}
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                key, eq, value = line.partition("=")
                if eq:
                    fields[key.strip()] = value.strip().strip("\"'")
            return fields
    raise ConfigError(f"no os-release under {root}")


def _rpm_packages(path: Path) -> list[InstalledPackage]:
    # Path.as_uri() escapes "?", "#" and spaces; the database is opened read-only and immutable,
    # so nothing is written beside it (no journal, no lock file).
    try:
        con = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
        try:
            con.execute("PRAGMA trusted_schema = OFF")
            rows = con.execute("SELECT blob FROM Packages").fetchall()
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise ConfigError(f"the RPM database at {path} could not be read: {exc}") from exc
    packages = []
    for (blob,) in rows:
        try:
            tags = read_header_blob(bytes(blob))
        except (RPMError, ValueError, IndexError):
            continue
        name, version_release, arch, epoch = identity(tags)
        if name and name != "gpg-pubkey":
            version = f"{epoch}:{version_release}" if epoch else version_release
            packages.append(InstalledPackage(name, version, arch))
    return packages


def _deb_packages(path: Path) -> list[InstalledPackage]:
    packages = []
    for block in re.split(r"\n\s*\n", path.read_text(encoding="utf-8", errors="replace")):
        fields = parse_fields(block)
        if not fields.get("Package") or "installed" not in fields.get("Status", "").split():
            continue
        source = fields.get("Source", "").split(" ", 1)[0] or None
        packages.append(
            InstalledPackage(
                fields["Package"], fields.get("Version", ""), fields.get("Architecture", ""), source
            )
        )
    return packages


def _components(root: Path) -> dict[str, str]:
    out = {}
    for candidate in ("sys/module/nvidia/version", "proc/driver/nvidia/version"):
        path = root / candidate
        if path.is_file():
            match = re.search(
                r"(\d+\.\d+(?:\.\d+)?)", path.read_text(encoding="utf-8", errors="replace")
            )
            if match:
                out["nvidiaDriver"] = match.group(1)
                break
    cuda = root / "usr/local/cuda/version.json"
    if cuda.is_file():
        try:
            version = json.loads(cuda.read_text(encoding="utf-8")).get("cuda", {}).get("version")
        except ValueError:
            version = None
        if version:
            out["cuda"] = str(version)
    return out


_DEB_FAMILY = frozenset({"debian", "ubuntu"})
RPM_LISTING = "rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\\n'"
DEB_LISTING = "dpkg-query -W -f='${Package} ${Version} ${Architecture} ${source:Package}\\n'"


def _listed_packages(path: Path, family: str) -> list[InstalledPackage]:
    """Packages from a listing made on the host: ``name version arch [source]`` per line."""
    packages = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) < 3:
            raise ConfigError(f"{path.name} line {number}: expected 'name version arch [source]'")
        name, version, arch = fields[:3]
        if family == "rpm":
            version = version.removeprefix("0:").removeprefix("(none):")
            if name == "gpg-pubkey":
                continue
        source = fields[3] if len(fields) > 3 and fields[3] != name else None
        packages.append(InstalledPackage(name, version, arch, source if family == "deb" else None))
    return packages


def collect(root: Path, label: str, now: datetime, package_list: Path | None = None) -> Inventory:
    """Inventory a Linux root filesystem without running anything from it.

    ``package_list`` replaces reading the package database: the output of ``RPM_LISTING`` or
    ``DEB_LISTING`` run on the host.
    """
    if not _LABEL.match(label):
        raise ConfigError("the label must be 1-64 letters, digits, dots, dashes or underscores")
    release = _os_release(root)
    like = {release.get("ID", "").lower(), *release.get("ID_LIKE", "").lower().split()}
    rpmdb = next((root / p for p in _RPMDBS if (root / p).is_file()), None)
    dpkg = root / "var/lib/dpkg/status"
    try:
        if package_list is not None:
            family = "deb" if like & _DEB_FAMILY else "rpm"
            packages = _listed_packages(package_list, family)
        elif rpmdb is not None:
            family, packages = "rpm", _rpm_packages(rpmdb)
        elif dpkg.is_file():
            family, packages = "deb", _deb_packages(dpkg)
        elif (root / "var/lib/rpm/Packages").is_file():
            raise ConfigError(
                "this host keeps its RPM database in the older Berkeley DB format, which "
                "superscrubber104 "
                f"does not read: run {RPM_LISTING} > packages.txt on it and pass "
                "--package-list packages.txt"
            )
        else:
            raise ConfigError(f"no RPM database or dpkg status under {root}")
    except OSError as exc:
        raise ConfigError(f"could not read the package data: {exc}") from exc
    os = OsIdentity(
        family, release.get("ID", ""), release.get("VERSION_ID", ""), release.get("PRETTY_NAME", "")
    )
    ordered = tuple(sorted(packages, key=lambda p: (p.name, p.arch, p.version)))
    return Inventory(label, now, os, ordered, _components(root))


def from_windows(hotfixes: Path, product: str, build: str, label: str, now: datetime) -> Inventory:
    """A Windows host from ``Get-HotFix | Select-Object HotFixID | ConvertTo-Json``."""
    if not _LABEL.match(label):
        raise ConfigError("the label must be 1-64 letters, digits, dots, dashes or underscores")
    try:
        data: Any = json.loads(hotfixes.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{hotfixes.name} is not the JSON Get-HotFix produces: {exc}") from exc
    entries = data if isinstance(data, list) else [data]
    kbs = sorted(
        {
            str(e.get("HotFixID", "")).upper()
            for e in entries
            if isinstance(e, dict) and str(e.get("HotFixID", "")).upper().startswith("KB")
        }
    )
    os = OsIdentity("windows", "windows", build, product)
    return Inventory(label, now, os, tuple(InstalledPackage(kb, "") for kb in kbs))


def sign(inventory: Inventory, signer: Signer) -> bytes:
    envelope = sign_envelope(PAYLOAD_TYPE, layout.encode(inventory), signer)
    return layout.encode(envelope.to_data())


def load(path: Path, keys: list[VerifyKey] | None = None) -> tuple[Inventory, list[str]]:
    """Read an inventory (signed or not). Returns it and the key ids that verified it."""
    document = json.loads(path.read_bytes())
    signers: list[str] = []
    if isinstance(document, dict) and "payloadType" in document:
        envelope = Envelope.from_data(document)
        if envelope.payload_type != PAYLOAD_TYPE:
            raise ConfigError(f"{path.name} is not an inventory")
        known = {k.key_id: k for k in keys or []}
        signers, bad = envelope.verified_by(known.get)
        if bad:
            raise ConfigError(f"{path.name}: the inventory signature does not verify")
        document = json.loads(envelope.payload)
    return from_data(Inventory, document), signers
