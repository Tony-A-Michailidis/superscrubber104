"""RPM and Debian package files, and RPM databases.

* **RPM files**: identity, licence, vendor, scriptlets; the header's SHA-256 and the payload digest
  are checked (a mismatch means the package was altered, and is final); the vendor's OpenPGP header
  signature is verified against the keys the policy pins for ``package.rpm``. A verified signature
  is recorded as a ``signature``-level verification on the file.
* **Debian files**: identity, dependencies and maintainer scripts from the control archive. A
  ``.deb`` carries no signature of its own: its authenticity comes from the repository's signed
  ``Release`` and ``Packages`` (doc 27), checked by the mirror assembler.
* **RPM databases** (``rpmdb.sqlite``) inside images and root filesystems: every installed package,
  read from memory, read-only, for the SBOM and vulnerability matching.
"""

import itertools
import re
import sqlite3
from urllib.parse import quote

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import (
    ArtifactRef,
    Component,
    ComponentType,
    LicenseRef,
    Subject,
    ToolRef,
    Verification,
)
from airlock.formats import openpgp
from airlock.formats.deb import DebError, read_deb
from airlock.formats.rpm import Package, RPMError, identity, read_header_blob, read_package
from airlock.handlers.common import TooLarge, full_path, name_of, read_bytes
from airlock.trust import signature_verification, verify_gpg

TOOL = ToolRef("airlock.linux-packages", __version__)
_DEB_NAME = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9.+-]*)_(?P<version>[^_]+)_(?P<arch>[a-z0-9-]+)\.deb$"
)
_RPMDB_LIMIT = 256 << 20


def rpm_purl(name: str, evr: str, arch: str, vendor: str | None, epoch: int | None) -> str:
    namespace = re.sub(r"[^a-z0-9]+", "", (vendor or "rpm").lower().split()[0]) or "rpm"
    qualifiers = [f"arch={arch}"] if arch else []
    if epoch:
        qualifiers.append(f"epoch={epoch}")
    version = evr.split(":", 1)[-1]
    return f"pkg:rpm/{namespace}/{quote(name)}@{quote(version, safe='')}" + (
        "?" + "&".join(qualifiers) if qualifiers else ""
    )


def deb_purl(name: str, version: str, arch: str, vendor: str = "debian") -> str:
    return f"pkg:deb/{vendor}/{quote(name)}@{quote(version, safe='')}" + (
        f"?arch={arch}" if arch else ""
    )


_RPM_RULES = (
    "package.digest-mismatch",
    "package.signature.invalid",
    "package.signature.untrusted",
    "package.signature.missing",
)


def _rpm_signature(
    view: ArtifactView, package: Package, ctx: Context
) -> tuple[openpgp.Result | None, str | None, bool]:
    """(result, anchor, whether the verified signature covers the payload too).

    A header signature covers the payload only through the payload digest the header records,
    and only if that digest was checked. Signatures over header and payload together (older
    packages) are verified over both. ``None``: the package is not signed at all.
    """
    if not package.header_signatures and not package.package_signatures:
        return None, None, False
    best: tuple[openpgp.Result, str | None, bool] = (
        openpgp.Result(False, reason="no readable signature"),
        None,
        False,
    )

    def consider(result: openpgp.Result, anchor: str | None, whole: bool) -> bool:
        nonlocal best
        better = (result.valid, whole, result.key is not None) > (
            best[0].valid,
            best[2],
            best[0].key is not None,
        )
        if better:
            best = (result, anchor, whole)
        return result.valid and whole

    for blob, whole in (
        *((b, package.payload_checked) for b in package.header_signatures),
        *((b, True) for b in package.package_signatures),
    ):
        try:
            signatures = openpgp.load_signatures(blob)
        except openpgp.OpenPGPError as exc:
            consider(openpgp.Result(False, reason=f"unreadable signature: {exc}"), None, False)
            continue
        for signature in signatures:
            if blob in package.header_signatures:
                result, anchor = verify_gpg(ctx, "package.rpm", signature, [package.header])
            else:
                with view.open() as stream:
                    stream.seek(package.payload_offset)
                    payload = iter(lambda s=stream: s.read(1 << 20), b"")  # type: ignore[misc]
                    chunks = itertools.chain([package.header], payload)
                    result, anchor = verify_gpg(ctx, "package.rpm", signature, chunks)
            if consider(result, anchor, whole):
                return best
    return best


def _rpm(view: ArtifactView, ctx: Context) -> Inspection:
    subject = Subject.of_artifact(view.ref)
    try:
        with view.open() as stream:
            package = read_package(stream)
    except (RPMError, OSError, ValueError, IndexError) as exc:
        # Unreadable is not the same as altered: nothing could be checked, and that is said.
        ctx.recorder.not_assessed(
            _RPM_RULES, subject, tool=TOOL, reason=f"the package could not be read: {exc}"
        )
        return Inspection(kind="package.rpm", metadata={"rpm": {"error": str(exc)[:300]}})
    if package.problems:
        ctx.recorder.fail(
            "package.digest-mismatch", subject, tool=TOOL, detail={"problems": package.problems}
        )
    elif package.header_sha256 or package.payload_checked:
        ctx.recorder.passed("package.digest-mismatch")
    verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
    result, anchor, whole = _rpm_signature(view, package, ctx)
    signer = result.signature.issuer if result and result.signature else None
    if result is None:
        ctx.recorder.fail("package.signature.missing", subject, tool=TOOL, detail={"format": "rpm"})
    else:
        ctx.recorder.passed("package.signature.missing")
        if result.valid:
            ctx.recorder.passed("package.signature.invalid")
            ctx.recorder.passed("package.signature.untrusted")
            if whole and not package.problems:
                verifications[view.ref] = (signature_verification(result, anchor),)
            elif not whole:
                ctx.recorder.not_assessed(
                    ("package.digest-mismatch",),
                    subject,
                    tool=TOOL,
                    reason="the header is signed, but it records no payload digest that could be "
                    "checked: the signature does not cover the payload",
                )
        elif result.key is not None:
            ctx.recorder.fail(
                "package.signature.invalid",
                subject,
                tool=TOOL,
                detail={"reason": result.reason, "key": result.key.fingerprint},
            )
        else:
            ctx.recorder.fail(
                "package.signature.untrusted",
                subject,
                tool=TOOL,
                detail={"reason": result.reason, "issuer": signer},
            )
    if package.scriptlets:
        ctx.recorder.fail(
            "package.maintainer-scripts", subject, tool=TOOL, detail={"scripts": package.scriptlets}
        )
    purl = rpm_purl(package.name, package.evr, package.arch, package.vendor, package.epoch)
    component = Component(
        bom_ref=f"{purl}#{view.sha256 or full_path(view.ref)}"[:300],
        type=ComponentType.LIBRARY,
        name=package.name,
        version=package.evr,
        purl=purl,
        licenses=(LicenseRef(name=package.licence),) if package.licence else (),
        supplier=package.vendor,
        hashes={"sha256": view.sha256} if view.sha256 else {},
        evidence=(view.ref,),
    )
    summary = {
        "name": package.name,
        "evr": package.evr,
        "arch": package.arch,
        "vendor": package.vendor,
        "sourceRpm": package.source_rpm,
        "scriptlets": package.scriptlets,
        "signedBy": signer,
        "signatureCoversPayload": whole if result is not None else None,
    }
    return Inspection(
        kind="package.rpm",
        metadata={"rpm": summary},
        components=(component,),
        verifications=verifications,
    )


def _deb(view: ArtifactView, ctx: Context) -> Inspection:
    note = None
    try:
        with view.open() as stream:
            package = read_deb(stream)
        name, version, arch = package.name, package.version, package.arch
        fields: dict[str, str] = {
            k: package.fields[k]
            for k in ("Depends", "Pre-Depends", "Provides", "Source")
            if k in package.fields
        }
        scripts: list[str] | None = package.scripts
    except (DebError, OSError, ValueError) as exc:
        match = _DEB_NAME.match(name_of(view.ref))
        name, version, arch = (
            (match["name"], match["version"].replace("%3a", ":"), match["arch"])
            if match
            else ("", "", "")
        )
        fields, scripts, note = {}, None, str(exc)
    if scripts is None:
        ctx.recorder.not_assessed(
            ("package.maintainer-scripts",),
            Subject.of_artifact(view.ref),
            tool=TOOL,
            reason=f"control archive not read: {note}",
        )
    vendor = "ubuntu" if "ubuntu" in version.lower() else "debian"
    purl = deb_purl(name, version, arch, vendor) if name else None
    components: tuple[Component, ...] = ()
    if purl:
        components = (
            Component(
                bom_ref=f"{purl}#{view.sha256 or full_path(view.ref)}"[:300],
                type=ComponentType.LIBRARY,
                name=name,
                version=version,
                purl=purl,
                hashes={"sha256": view.sha256} if view.sha256 else {},
                evidence=(view.ref,),
            ),
        )
    if scripts:
        ctx.recorder.fail(
            "package.maintainer-scripts",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"scripts": scripts},
        )
    summary: dict[str, object] = {
        "name": name,
        "version": version,
        "arch": arch,
        "scripts": scripts,
        **fields,
    }
    if note:
        summary["note"] = note
    return Inspection(kind="package.deb", metadata={"deb": summary}, components=components)


def _rpmdb(view: ArtifactView, ctx: Context) -> Inspection:
    subject = Subject.of_artifact(view.ref)
    try:
        data = read_bytes(view, _RPMDB_LIMIT)
        con = sqlite3.connect(":memory:")
        try:
            con.deserialize(data)
            con.execute("PRAGMA trusted_schema = OFF")
            con.execute("PRAGMA query_only = ON")
            rows = con.execute("SELECT blob FROM Packages").fetchall()
        finally:
            con.close()
    except (TooLarge, sqlite3.DatabaseError, OSError) as exc:
        ctx.recorder.not_assessed(
            ("inventory.artifact.unclassified",),
            subject,
            tool=TOOL,
            reason=f"the RPM database could not be read; its packages are not in the SBOM: {exc}",
        )
        return Inspection(kind="os.rpmdb", metadata={"osPackages": {"parsed": False}})
    components = []
    unreadable = 0
    for (blob,) in rows:
        try:
            tags = read_header_blob(bytes(blob))
        except (RPMError, ValueError, IndexError):
            unreadable += 1
            continue
        name, vr, arch, epoch = identity(tags)
        if not name or name == "gpg-pubkey":
            continue
        vendor = tags.get(1011)
        evr = f"{epoch}:{vr}" if epoch else vr
        purl = rpm_purl(name, evr, arch, vendor if isinstance(vendor, str) else None, epoch)
        components.append(
            Component(
                bom_ref=f"{purl}#{full_path(view.ref)}"[:300],
                type=ComponentType.LIBRARY,
                name=name,
                version=evr,
                purl=purl,
                evidence=(view.ref,),
            )
        )
    return Inspection(
        kind="os.rpmdb",
        metadata={"osPackages": {"packages": len(components), "unreadable": unreadable}},
        components=tuple(components),
    )


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref).lower()
    head = view.head(8)
    if name.endswith(".rpm") and head.startswith(b"\xed\xab\xee\xdb"):
        return "package.rpm"
    if name.endswith(".deb") and head.startswith(b"!<arch>\n"):
        return "package.deb"
    if full_path(view.ref).endswith("rpm/rpmdb.sqlite") and view.head(16).startswith(
        b"SQLite format 3"
    ):
        return "os.rpmdb"
    return None


class LinuxPackageHandler:
    name = "linux-packages"
    version = "1"
    kinds = frozenset({"package.rpm", "package.deb", "os.rpmdb"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 85) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact)
        if kind == "package.rpm":
            return _rpm(artifact, ctx)
        if kind == "package.deb":
            return _deb(artifact, ctx)
        return _rpmdb(artifact, ctx)
