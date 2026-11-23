"""Trivy: known vulnerabilities in container images, root filesystems and language packages.

Trivy always runs offline, against the vulnerability database in the cache directory the policy
names (``--skip-db-update --skip-java-db-update --offline-scan``). Its age is read from the
database's own ``metadata.json``.

What is scanned, so that each finding lands on the artifact that carries the package:

* every container image in the delivery (``docker save`` or OCI archive, OCI layout directory)
  with ``trivy image --input``;
* every root filesystem that is a directory of the delivery (it has ``etc/os-release``) with
  ``trivy rootfs``;
* every other language package superscrubber104 identified (wheels, sdists, installed distributions,
  npm tarballs and installed packages, ...) through a CycloneDX SBOM, with ``trivy sbom``. Findings
  are mapped back through the SBOM's ``bom-ref``.

Root filesystems inside archives that are not images cannot be given to Trivy without unpacking
them; their OS packages are recorded as not assessed.
"""

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from superscrubber104.core.canonical import JSON
from superscrubber104.core.interfaces import Context
from superscrubber104.core.model import (
    Analysis,
    ArtifactRef,
    Component,
    ComponentType,
    Severity,
    Subject,
)
from superscrubber104.core.policy import PluginPolicy
from superscrubber104.scanners.base import DataInfo, Ready, ScanError, Target
from superscrubber104.scanners.kev import KevFeed

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.MEDIUM,
}
_LANGUAGE_PURLS = (
    "pkg:pypi/", "pkg:npm/", "pkg:maven/", "pkg:golang/", "pkg:cargo/", "pkg:nuget/",
    "pkg:gem/", "pkg:composer/", "pkg:hex/", "pkg:pub/", "pkg:swift/", "pkg:cocoapods/",
    "pkg:conan/",
)  # fmt: skip
_OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
_IMAGE_KINDS = ("container.image.archive", "container.image.oci-layout")


@dataclass(frozen=True, slots=True)
class _Job:
    """One Trivy run and where its findings belong."""

    label: str
    args: tuple[str, ...]
    subject: ArtifactRef | None  # None: map through the SBOM


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _within(ref: ArtifactRef, prefixes: Iterable[str]) -> bool:
    return any(ref.path == p or ref.path.startswith(p.rstrip("/") + "/") for p in prefixes if p)


def _cvss(vuln: dict[str, object]) -> str | None:
    scores: list[float] = []
    cvss = vuln.get("CVSS")
    if isinstance(cvss, dict):
        for source in cvss.values():
            if isinstance(source, dict):
                for key in ("V3Score", "V40Score"):
                    score = source.get(key)
                    if isinstance(score, int | float):
                        scores.append(float(score))
    return f"{max(scores):.1f}" if scores else None


def sbom_document(components: Sequence[Component]) -> dict[str, JSON]:
    """A minimal CycloneDX 1.5 document: enough for a scanner to match packages by purl."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "superscrubber104-delivery"}},
        "components": [
            {
                "bom-ref": c.bom_ref,
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
            }
            for c in components
        ],
    }


class Trivy:
    name = "trivy"
    capability = "vulnerabilities"
    rules: tuple[str, ...] = ("vuln.component.known",)
    binary_names: tuple[str, ...] = ("trivy",)

    def __init__(self, kev: KevFeed | None = None) -> None:
        self.kev = kev or KevFeed()

    def version(self, ready: Ready) -> str | None:
        out = ready.run(["--version"]).stdout
        for line in out.splitlines():
            if line.strip().lower().startswith("version:"):
                return line.split(":", 1)[1].strip().lstrip("v")
        return None

    def data(self, policy: PluginPolicy) -> DataInfo:
        cache = policy.database
        if cache is None:
            return DataInfo(
                problem="plugins.trivy.database (the Trivy cache directory) is not set; "
                "superscrubber104 "
                "does not let Trivy download a database"
            )
        meta_path = cache / "db" / "metadata.json"
        if not (cache / "db" / "trivy.db").is_file() or not meta_path.is_file():
            return DataInfo(problem=f"no Trivy vulnerability database in {cache / 'db'}")
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return DataInfo(problem=f"unreadable {meta_path}: {exc}")
        meta = meta if isinstance(meta, dict) else {}
        built = _parse_time(meta.get("UpdatedAt"))
        files = ["db/trivy.db", "db/metadata.json"]
        for name in ("java-db/trivy-java.db", "java-db/metadata.json"):
            if (cache / name).is_file():
                files.append(name)
        version = f"schema {meta.get('Version')}" + (f", {built:%Y-%m-%d}" if built else "")
        return DataInfo(version=version, built_at=built, files=tuple(files))

    # --- scanning -------------------------------------------------------------------------------

    def _common(self, ready: Ready) -> list[str]:
        assert ready.policy.database is not None  # noqa: S101 - checked by data()
        return [
            "--cache-dir",
            str(ready.policy.database),
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--quiet",
            "--timeout",
            f"{int(ready.policy.timeout.total_seconds())}s",
            *ready.policy.args,
        ]

    def plan(
        self, targets: Sequence[Target], analysis: Analysis, ctx: Context, ready: Ready
    ) -> tuple[list[_Job], list[Component], set[str]]:
        """Jobs to run, components to scan through an SBOM, and the prefixes already covered."""
        by_path = {t.ref.path: t for t in targets}
        jobs: list[_Job] = []
        covered: set[str] = set()
        for artifact in analysis.artifacts:
            if artifact.ref.member or not set(artifact.kinds) & set(_IMAGE_KINDS):
                continue
            target = by_path.get(artifact.ref.path)
            if target is None:
                continue
            if "container.image.oci-layout" in artifact.kinds:
                location, prefix = target.location.parent, artifact.ref.path.rpartition("/")[0]
            else:
                location, prefix = target.location, artifact.ref.path
            covered.add(prefix)
            jobs.append(_Job(prefix or ".", ("image", "--input", str(location)), artifact.ref))
        for component in analysis.components:
            if component.type is not ComponentType.OPERATING_SYSTEM:
                continue
            for ref in component.evidence:
                if _within(ref, covered):
                    continue
                suffix = next((s for s in _OS_RELEASE if ref.path.endswith(s)), None)
                if suffix is None:
                    continue
                prefix = ref.path[: -len(suffix)].rstrip("/")
                target = by_path.get(ref.path)
                if ref.member or target is None:
                    ctx.recorder.not_assessed(
                        self.rules,
                        Subject.of_artifact(ref),
                        tool=ready.tool,
                        reason="a root filesystem inside an archive that is not a container "
                        "image; its OS packages were not scanned",
                    )
                    continue
                root = target.location
                for _ in suffix.split("/"):
                    root = root.parent
                covered.add(prefix)
                jobs.append(_Job(prefix or ".", ("rootfs", str(root)), ArtifactRef(ref.path)))
        packages = [
            c
            for c in analysis.components
            if c.purl
            and c.version
            and c.purl.startswith(_LANGUAGE_PURLS)
            and c.evidence
            and not all(_within(ref, covered) for ref in c.evidence)
        ]
        return jobs, packages, covered

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        jobs, packages, _ = self.plan(targets, analysis, ctx, ready)
        components = {c.bom_ref: c for c in packages}
        by_purl = {c.purl: c for c in packages if c.purl}
        if packages:
            sbom = ready.workdir / "delivery.cdx.json"
            sbom.write_text(json.dumps(sbom_document(packages)), encoding="utf-8")
            jobs.append(_Job("packages", ("sbom", str(sbom)), None))
        if not jobs:  # no result is not a clean result: say why nothing was scanned
            ctx.recorder.not_assessed(
                self.rules,
                Subject.bundle(),
                tool=ready.tool,
                reason="the delivery holds no container image, root filesystem or package for "
                "Trivy to scan; dependencies declared without their packages (see "
                "*.environment.unresolvable) were not checked",
            )
            return
        failures = 0
        for job in jobs:
            output = ready.workdir / f"trivy-{len(list(ready.workdir.glob('trivy-*')))}.json"
            try:
                ready.run([*job.args, *self._common(ready), "--output", str(output)])
                report = json.loads(output.read_text(encoding="utf-8"))
            except (ScanError, OSError, ValueError) as exc:
                failures += 1
                subject = Subject.of_artifact(job.subject) if job.subject else Subject.bundle()
                ctx.recorder.error(
                    "plugin.scan.error", subject, tool=ready.tool, error=f"{job.label}: {exc}"
                )
                if job.subject is not None:
                    ctx.recorder.not_assessed(
                        self.rules, subject, tool=ready.tool, reason="Trivy did not complete"
                    )
                continue
            clean = self._report(report, job, components, by_purl, ctx, ready)
            ctx.recorder.passed("vuln.component.known", clean)
        if failures and failures == len(jobs):
            raise ScanError("every Trivy run failed")

    def _report(
        self,
        report: object,
        job: _Job,
        components: dict[str, Component],
        by_purl: dict[str, Component],
        ctx: Context,
        ready: Ready,
    ) -> int:
        """Record findings from one report; returns the number of clean results."""
        if not isinstance(report, dict):
            raise ScanError("Trivy report is not a JSON object")
        results = report.get("Results") or []
        clean = 0
        vulnerable: set[str] = set()
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            vulns = result.get("Vulnerabilities") or []
            if not vulns:
                clean += 1
                continue
            for vuln in vulns:
                if isinstance(vuln, dict):
                    ref = self._finding(vuln, result, job, components, by_purl, ctx, ready)
                    if ref:
                        vulnerable.add(ref)
        if job.subject is None:  # SBOM: count components without findings
            clean = len(components) - len(vulnerable & set(components))
        return max(clean, 0)

    def _finding(
        self,
        vuln: dict[str, object],
        result: dict[str, object],
        job: _Job,
        components: dict[str, Component],
        by_purl: dict[str, Component],
        ctx: Context,
        ready: Ready,
    ) -> str | None:
        vid = str(vuln.get("VulnerabilityID") or "unknown")
        package = str(vuln.get("PkgName") or "unknown")
        installed = str(vuln.get("InstalledVersion") or "")
        ident = vuln.get("PkgIdentifier") if isinstance(vuln.get("PkgIdentifier"), dict) else {}
        assert isinstance(ident, dict)  # noqa: S101
        component: Component | None = None
        if job.subject is None:
            component = components.get(str(ident.get("BOMRef") or "")) or by_purl.get(
                str(ident.get("PURL") or "")
            )
            if component is None or not component.evidence:
                return None
            ref = component.evidence[0]
        else:
            ref = job.subject
        fixed = str(vuln.get("FixedVersion") or "")
        vendor_ids = vuln.get("VendorIDs")
        aliases = (
            [vid, *(v for v in vendor_ids if isinstance(v, str))]
            if isinstance(vendor_ids, list)
            else [vid]
        )
        severity_name = str(vuln.get("Severity") or "UNKNOWN").upper()
        ctx.recorder.fail(
            "vuln.component.known",
            Subject.of_artifact(ref, locator=f"{package}@{installed}"),
            tool=ready.tool,
            detail={
                "id": vid,
                "package": package,
                "installedVersion": installed,
                "fixedVersion": fixed or None,
                "status": vuln.get("Status"),
                "severity": severity_name,
                "cvss": _cvss(vuln),
                "title": str(vuln.get("Title") or "")[:300] or None,
                "url": vuln.get("PrimaryURL"),
                "target": result.get("Target"),
                "purl": ident.get("PURL"),
                "alsoIn": [r.display for r in component.evidence[1:20]] if component else None,
            },
            attributes={
                "id": vid,
                "severity": severity_name.lower(),
                "package": package,
                "ecosystem": str(result.get("Type") or ""),
                "fixed": "true" if fixed else "false",
                "kev": self.kev.mark(*aliases),
                "scanner": self.name,
            },
            severity=_SEVERITY.get(severity_name, Severity.MEDIUM),
            discriminator=f"{vid}|{package}|{installed}|{result.get('Target')}",
        )
        return component.bom_ref if component else None
