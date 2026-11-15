"""Java: jars and poms in Maven or Gradle layouts, sidecar checksums, Gradle lockfiles and
dependency verification metadata.

* ``.jar``/``.war``/``.aar`` and ``.pom`` files: identity from ``META-INF/maven/**/pom.properties``,
  the pom itself, or the repository layout (``<group path>/<artifact>/<version>/<file>`` for
  Maven, ``files-2.1/<group>/<artifact>/<version>/<sha1>/<file>`` for Gradle's cache). In a Gradle
  cache the directory name is the file's sha1, and is checked.
* Sidecar checksums (``.sha512``/``.sha256``/``.sha1``/``.md5``) published with Maven artifacts are
  compared (``package.checksum-mismatch``, final). Detached ``.asc`` signatures are verified by the
  upstream handler (doc 27) against keys pinned for ``file.signed``.
* ``gradle.lockfile`` (versions) and ``gradle/verification-metadata.xml`` (versions and hashes per
  file) are lockfiles: each entry must be satisfiable from the delivery, with a matching hash where
  one is recorded.

Jar signatures (``META-INF/*.SF``) are recorded, not verified (doc 29). ``pom.xml`` dependency
lists are not resolved: without a lockfile, versions come from parents, BOMs and ranges, which
would take a Maven resolver to decide.
"""

import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from urllib.parse import quote

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import ArtifactRef, Subject, ToolRef, UnitClaim, UnitKind, Verification
from airlock.formats.deb import parse_fields
from airlock.handlers.common import TooLarge, full_path, name_of, read_bytes, read_text
from airlock.handlers.packages.locked import (
    check_sidecar,
    component,
    digest_hex,
    distribution_claim,
    lockfile_claim,
    requirement,
    sidecar,
)

TOOL = ToolRef("airlock.jvm", __version__)
KIND = UnitKind.JVM_ENVIRONMENT
_ARCHIVES = (".jar", ".war", ".aar", ".ear")
_SIDECARS = ((".sha512", "sha512"), (".sha256", "sha256"), (".sha1", "sha1"), (".md5", "md5"))
_LOCK_LINE = re.compile(r"^(?P<group>[^:#\s]+):(?P<artifact>[^:\s]+):(?P<version>[^=\s]+)=")
_SHA1_DIR = re.compile(r"^[0-9a-f]{40}$")
_POM_LIMIT = 4 << 20


@dataclass(frozen=True, slots=True)
class Coordinates:
    group: str
    artifact: str
    version: str


def maven_purl(c: Coordinates) -> str:
    return f"pkg:maven/{quote(c.group)}/{quote(c.artifact)}@{quote(c.version, safe='')}"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def pom_coordinates(data: bytes) -> Coordinates | None:
    try:
        root = ET.fromstring(data)  # noqa: S314 - see the import
    except ET.ParseError:
        return None
    values: dict[str, str] = {}
    parent: dict[str, str] = {}
    for child in root:
        name = _local(child.tag)
        if name in ("groupId", "artifactId", "version"):
            values[name] = (child.text or "").strip()
        elif name == "parent":
            parent = {_local(p.tag): (p.text or "").strip() for p in child}
    group = values.get("groupId") or parent.get("groupId")
    version = values.get("version") or parent.get("version")
    artifact = values.get("artifactId")
    if group and artifact and version and "${" not in group + version:
        return Coordinates(group, artifact, version)
    return None


def _from_layout(path: str) -> tuple[Coordinates | None, str | None]:
    """Coordinates from the directory layout, and the sha1 a Gradle cache path records."""
    parts = path.split("/")
    if "files-2.1" in parts:
        at = len(parts) - 1 - parts[::-1].index("files-2.1")
        rest = parts[at + 1 :]
        if len(rest) == 5 and _SHA1_DIR.match(rest[3]):
            return Coordinates(rest[0], rest[1], rest[2]), rest[3]
    if len(parts) >= 4:
        artifact, version, file = parts[-3], parts[-2], parts[-1]
        if file.startswith(f"{artifact}-{version}"):
            return Coordinates(
                "", artifact, version
            ), None  # group unknown: where does the root end?
    return None, None


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref).lower()
    if name == "gradle.lockfile" or (
        name.endswith(".lockfile") and "gradle/dependency-locks" in full_path(view.ref)
    ):
        return "gradle.lockfile"
    if name == "verification-metadata.xml":
        return "gradle.verification-metadata"
    if name.endswith(_ARCHIVES) and view.head(4) == b"PK\x03\x04":
        return "java.archive"
    if name.endswith(".pom") and b"<project" in view.head(4096):
        return "maven.pom"
    return None


class JvmHandler:
    name = "jvm"
    version = "1"
    kinds = frozenset(
        {"java.archive", "maven.pom", "gradle.lockfile", "gradle.verification-metadata"}
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 85) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact)
        if kind == "gradle.lockfile":
            return self._gradle_lockfile(artifact)
        if kind == "gradle.verification-metadata":
            return self._verification_metadata(artifact)
        return self._artifact(artifact, ctx, kind or "java.archive")

    # --- lockfiles ------------------------------------------------------------------------------

    def _gradle_lockfile(self, view: ArtifactView) -> Inspection:
        requirements = []
        for line in read_text(view, 16 << 20).splitlines():
            if match := _LOCK_LINE.match(line.strip()):
                requirements.append(
                    requirement(f"{match['group']}:{match['artifact']}", match["version"])
                )
        claim = lockfile_claim(view, KIND, "maven", "gradle.lockfile", requirements)
        return Inspection(
            kind="gradle.lockfile",
            metadata={"gradleLock": {"entries": len(requirements)}},
            claims=(claim,),
        )

    def _verification_metadata(self, view: ArtifactView) -> Inspection:
        try:
            root = ET.fromstring(read_bytes(view, 64 << 20))  # noqa: S314 - see the import
        except (ET.ParseError, TooLarge) as exc:
            return Inspection(
                kind="gradle.verification-metadata",
                metadata={"gradleVerification": {"error": str(exc)[:300]}},
            )
        requirements = []
        for element in root.iter():
            if _local(element.tag) != "component":
                continue
            group, module, version = (
                element.get("group"),
                element.get("name"),
                element.get("version"),
            )
            for item in element:
                if _local(item.tag) != "artifact" or not item.get("name"):
                    continue
                hashes = [
                    f"{_local(h.tag)}:{h.get('value', '').lower()}"
                    for h in item.iter()
                    if _local(h.tag) in ("sha256", "sha512", "sha1", "md5") and h.get("value")
                ]
                requirements.append(
                    requirement(f"{group}:{module}:{item.get('name')}", str(version), hashes)
                )
        claim = lockfile_claim(view, KIND, "maven", "verification-metadata.xml", requirements)
        summary = {"artifacts": len(requirements)}
        return Inspection(
            kind="gradle.verification-metadata",
            metadata={"gradleVerification": summary},
            claims=(claim,),
        )

    # --- jars and poms --------------------------------------------------------------------------

    def _artifact(self, view: ArtifactView, ctx: Context, kind: str) -> Inspection:
        coordinates, signed, error = None, False, None
        if kind == "java.archive":
            try:
                with view.open() as stream, zipfile.ZipFile(stream) as archive:
                    names = archive.namelist()
                    signed = any(
                        re.fullmatch(r"META-INF/[^/]+\.SF", n, re.IGNORECASE) for n in names
                    )
                    poms = [
                        n
                        for n in names
                        if n.startswith("META-INF/maven/") and n.endswith("/pom.properties")
                    ]
                    if len(poms) == 1:
                        props = parse_fields(
                            archive.read(poms[0]).decode("utf-8", "replace").replace("=", ":")
                        )
                        if (
                            props.get("groupId")
                            and props.get("artifactId")
                            and props.get("version")
                        ):
                            coordinates = Coordinates(
                                props["groupId"], props["artifactId"], props["version"]
                            )
            except (zipfile.BadZipFile, OSError) as exc:
                error = str(exc)[:300]
        else:
            try:
                coordinates = pom_coordinates(read_bytes(view, _POM_LIMIT))
            except TooLarge:
                coordinates = None
        layout, recorded_sha1 = _from_layout(full_path(view.ref))
        if coordinates is None and layout is not None and layout.group:
            coordinates = layout
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        checks: list[Verification] = []
        if recorded_sha1 is not None:  # the Gradle cache names the directory after the sha1
            actual = digest_hex(view, "sha1")
            if actual != recorded_sha1:
                ctx.recorder.fail(
                    "package.checksum-mismatch",
                    Subject.of_artifact(view.ref),
                    tool=TOOL,
                    detail={
                        "recordedIn": "gradle cache path",
                        "algorithm": "sha1",
                        "recorded": recorded_sha1,
                        "actual": actual,
                    },
                )
        found = sidecar(view, _SIDECARS)
        if found is not None:
            algorithm, text, source = found
            check = check_sidecar(view, ctx, TOOL, algorithm, text, source, "maven-checksum")
            if check is not None:
                checks.append(check)
        if checks:
            verifications[view.ref] = tuple(checks)
        metadata = {
            "group": coordinates.group if coordinates else None,
            "artifact": coordinates.artifact if coordinates else None,
            "version": coordinates.version if coordinates else None,
            "signedJar": signed if kind == "java.archive" else None,
            "error": error,
        }
        if coordinates is None:
            return Inspection(kind=kind, metadata={"maven": metadata}, verifications=verifications)
        purl = maven_purl(coordinates)
        components = (
            (component(view, coordinates.artifact, coordinates.version, purl),)
            if kind == "java.archive"
            else ()
        )
        bom_ref = components[0].bom_ref if components else None
        hashes = [f"sha256:{view.sha256}"]
        key = f"{coordinates.group}:{coordinates.artifact}"
        claims: tuple[UnitClaim, ...] = (
            distribution_claim(view, KIND, "maven", key, coordinates.version, hashes, bom_ref),
            distribution_claim(
                view,
                KIND,
                "maven",
                f"{key}:{name_of(view.ref)}",
                coordinates.version,
                hashes,
                bom_ref,
            ),
        )
        return Inspection(
            kind=kind,
            metadata={"maven": metadata},
            components=components,
            claims=claims,
            verifications=verifications,
        )
