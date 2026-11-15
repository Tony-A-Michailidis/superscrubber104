"""``airlock patch inventory``: what is installed on a high-side host, signed, to cross outbound.

Read statically from a root filesystem (the host's ``/``, a mounted image, a container export):
``etc/os-release``, the RPM database (``rpmdb.sqlite``) or dpkg's ``status``. Windows hosts are
inventoried from what PowerShell reports (``Get-HotFix`` and the OS build, see doc 33), since
airlock runs on Linux.

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

from airlock.core.errors import ConfigError
from airlock.core.model import API_VERSION
from airlock.core.serde import from_data, to_data
from airlock.core.signing import Envelope, Signer, VerifyKey, sign_envelope
from airlock.formats.deb import parse_fields
from airlock.formats.rpm import RPMError, identity, read_header_blob

PAYLOAD_TYPE = "application/vnd.airlock.inventory+json"
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
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        con.execute("PRAGMA trusted_schema = OFF")
        rows = con.execute("SELECT blob FROM Packages").fetchall()
    finally:
        con.close()
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


def collect(root: Path, label: str, now: datetime) -> Inventory:
    """Inventory a Linux root filesystem without running anything from it."""
    if not _LABEL.match(label):
        raise ConfigError("the label must be 1-64 letters, digits, dots, dashes or underscores")
    release = _os_release(root)
    rpmdb = next((root / p for p in _RPMDBS if (root / p).is_file()), None)
    dpkg = root / "var/lib/dpkg/status"
    if rpmdb is not None:
        family, packages = "rpm", _rpm_packages(rpmdb)
    elif dpkg.is_file():
        family, packages = "deb", _deb_packages(dpkg)
    else:
        raise ConfigError(f"no RPM database or dpkg status under {root}")
    os = OsIdentity(
        family, release.get("ID", ""), release.get("VERSION_ID", ""), release.get("PRETTY_NAME", "")
    )
    ordered = tuple(sorted(packages, key=lambda p: (p.name, p.arch, p.version)))
    return Inventory(label, now, os, ordered, _components(root))


def from_windows(hotfixes: Path, product: str, build: str, label: str, now: datetime) -> Inventory:
    """A Windows host from ``Get-HotFix | Select-Object HotFixID | ConvertTo-Json``."""
    if not _LABEL.match(label):
        raise ConfigError("the label must be 1-64 letters, digits, dots, dashes or underscores")
    data: Any = json.loads(hotfixes.read_text(encoding="utf-8-sig"))
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
    from airlock import bundle as layout

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


def encode(inventory: Inventory) -> object:
    return to_data(inventory)
