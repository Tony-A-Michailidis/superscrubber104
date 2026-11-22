"""Zarf packages (``zarf-package-*.tar[.zst]``, ``zarf-init-*.tar[.zst]``), read without Zarf.

A Zarf package is a tar, zstd-compressed by default, holding ``zarf.yaml`` (the definition),
``checksums.txt`` (a sha256 for every other file), optionally ``zarf.bundle.sig`` (a Sigstore
bundle signing ``zarf.yaml``), component tars, an OCI image layout under ``images/``, and SBOMs.
The definition binds the checksums through its aggregate checksum (the sha256 of
``checksums.txt``), so a verified signature over ``zarf.yaml`` vouches for every listed file.

One streaming pass hashes every member (and the files inside each component tar) and keeps only
the small control files and image documents. Then:

* **Checksum chain.** The aggregate checksum, every listed file, and the checksum ``zarf.yaml``
  records for each component file are records that travelled with the content: a mismatch, a
  listed file that is absent, and a file nothing lists are final.
* **Signature.** Verified offline against ``trust.upstream`` keys with scope ``zarf.package``:
  keyless (``type: sigstore``) or a key or certificate (``type: x509``).
* **Images.** The container checks run over ``images/``, and every image a component deploys
  must be there (unless the package is differential).
* **What deploying would do.** ``onDeploy`` and ``onRemove`` commands and files written to host
  paths are reported for review.

Everything inside (charts, manifests, host files, image layers and the models in them) is
inspected by the other handlers through the ordinary archive walk. Nothing in the package is run.
"""

import hashlib
import re
import tarfile
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import IO, Any

import yaml

from superscrubber104 import __version__
from superscrubber104.archive import (
    ARCHIVE_ERRORS,
    ZSTD,
    ZSTD_ADVICE,
    ExpansionLimit,
    capped,
    decompress,
    detect_format,
)
from superscrubber104.core.canonical import jsonable
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import (
    ArtifactRef,
    Result,
    Subject,
    ToolRef,
    TrustLevel,
    UnitClaim,
    UnitKind,
    Verification,
)
from superscrubber104.core.paths import check_member_name
from superscrubber104.core.yamlio import load_untrusted_yaml
from superscrubber104.formats.sigstore import BundleError, DigestMismatch, Outcome, parse_bundle
from superscrubber104.handlers.ai.signature import verify_bundle
from superscrubber104.handlers.common import name_of
from superscrubber104.handlers.containers import MemoryStore, inspect_store, report_conflicts
from superscrubber104.walker import BytesView

TOOL = ToolRef("superscrubber104.zarf", __version__)
SCOPE = "zarf.package"
KIND = "zarf.package"
SCHEMAS = (None, "zarf.dev/v1alpha1", "zarf.dev/v1beta1")
RULES = (
    "zarf.package.checksum-mismatch",
    "zarf.package.incomplete",
    "zarf.package.unlisted",
    "zarf.component.actions",
    "zarf.component.host-files",
    "zarf.package.differential",
    "package.member.conflicting-copies",
    "upstream.signature.invalid",
    "upstream.signature.untrusted",
)

_NAME = re.compile(r"^zarf-(?:package|init)-.+\.tar(?:\.zst)?$", re.IGNORECASE)
_CONTROL = ("zarf.yaml", "checksums.txt", "zarf.bundle.sig")
_PROVENANCE = frozenset({"zarf.yaml", "checksums.txt", "zarf.bundle.sig"})
_CONTROL_LIMIT = 16 << 20  # a larger zarf.yaml or checksums.txt is not read
_DOCUMENT_LIMIT = 4 << 20  # image index, manifests and configs
_DOCUMENTS_TOTAL = 64 << 20
_TEMP = "###ZARF_TEMP###"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_BLOCK = 1 << 20


# --- one streaming pass ---------------------------------------------------------------------------


class _Tee:
    """Reads a stream for an inner reader while hashing every byte that goes by."""

    def __init__(self, stream: IO[bytes], digest: Any) -> None:
        self.stream, self.digest, self.size = stream, digest, 0

    def read(self, n: int = -1) -> bytes:
        data = self.stream.read(n)
        self.digest.update(data)
        self.size += len(data)
        return data

    def drain(self) -> None:
        while self.read(_BLOCK):
            pass


@dataclass
class _Contents:
    digests: dict[str, str] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)
    duplicates: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    control: dict[str, bytes] = field(default_factory=dict)
    # later copies of control files (zarf.yaml held twice): every copy is checked
    control_copies: dict[str, list[bytes]] = field(default_factory=lambda: defaultdict(list))
    oversized: list[str] = field(default_factory=list)
    documents: dict[str, bytes] = field(default_factory=dict)  # images/, small JSON only
    # component tar -> inner file name -> (sha256, size, mode)
    components: dict[str, dict[str, tuple[str, int, int]]] = field(default_factory=dict)
    unreadable_components: dict[str, str] = field(default_factory=dict)


def _hash(stream: IO[bytes], keep: int = 0, json_only: bool = False) -> tuple[str, int, bytes]:
    """sha256 and size of ``stream``, and its bytes if it is at most ``keep`` long."""
    digest, size, kept = hashlib.sha256(), 0, bytearray()
    first = True
    while block := stream.read(_BLOCK):
        if first and json_only and block.lstrip()[:1] != b"{":
            keep = 0
        first = False
        digest.update(block)
        size += len(block)
        if size <= keep:
            kept += block
    return digest.hexdigest(), size, bytes(kept) if size <= keep else b""


def _component(name: str, stream: IO[bytes], contents: _Contents) -> tuple[str, int]:
    """Hash a component tar and every file in it, in one read."""
    tee = _Tee(stream, hashlib.sha256())
    files: dict[str, tuple[str, int, int]] = {}
    try:
        with tarfile.open(fileobj=tee, mode="r|") as inner:  # type: ignore[call-overload]
            for item in inner:
                inner_name, _ = check_member_name(item.name)
                if not inner_name or not item.isfile():
                    continue
                handle = inner.extractfile(item)
                if handle is None:
                    continue
                sha, size, _ = _hash(handle)
                files.setdefault(inner_name, (sha, size, item.mode))
        contents.components[name] = files
    except ARCHIVE_ERRORS as exc:
        if isinstance(exc, ExpansionLimit):
            raise
        contents.unreadable_components[name] = f"{type(exc).__name__}: {exc}"[:200]
    tee.drain()
    return tee.digest.hexdigest(), tee.size


def _read(stream: IO[bytes]) -> _Contents:
    contents = _Contents()
    documents_left = _DOCUMENTS_TOTAL
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name, _ = check_member_name(member.name)
            if not name or not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            kept = b""
            if name.startswith("components/") and name.endswith(".tar"):
                sha, size = _component(name, handle, contents)
            elif name in _CONTROL:
                sha, size, kept = _hash(handle, _CONTROL_LIMIT)
                if size > _CONTROL_LIMIT:
                    contents.oversized.append(name)
            elif name.startswith("images/") and name.count("/") <= 3:
                limit = min(_DOCUMENT_LIMIT, documents_left)
                sha, size, kept = _hash(handle, limit, json_only=name != "images/oci-layout")
                documents_left -= len(kept)
            else:
                sha, size, _ = _hash(handle)
            if name in contents.digests:
                contents.duplicates[name].append(sha)
                if kept and name in _CONTROL:
                    contents.control_copies[name].append(kept)
                continue
            contents.digests[name], contents.sizes[name] = sha, size
            if kept and name in _CONTROL:
                contents.control[name] = kept
            elif kept:
                contents.documents[name.removeprefix("images/")] = kept
    return contents


@contextmanager
def _open(view: ArtifactView, ctx: Context) -> Iterator[IO[bytes]]:
    """The package's tar stream: as is, or decompressed within the expansion limit."""
    with view.open() as raw:
        if detect_format(view.head(512)) == "zstd":
            limit = ctx.policy.limits.archive.allowance(view.size)  # ratio and size
            with decompress("zstd", raw) as expanded:
                yield capped(expanded, limit)
        else:
            yield raw


# --- the definition -------------------------------------------------------------------------------


def _map(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def normalise_image(reference: str) -> str:
    """A container image reference in full: ``registry/repository:tag`` (or ``@digest``)."""
    name = reference.strip()
    first, _, rest = name.partition("/")
    if not rest or ("." not in first and ":" not in first and first != "localhost"):
        name = f"docker.io/{name}" if rest else f"docker.io/library/{name}"
    elif first in ("index.docker.io", "registry-1.docker.io"):
        name = f"docker.io/{rest}"
    if name.startswith("docker.io/") and name.count("/") == 1:
        name = "docker.io/library/" + name.removeprefix("docker.io/")
    last = name.rsplit("/", 1)[-1]
    if ":" not in last and "@" not in last:
        name += ":latest"
    return name


def _image_names(component: dict[str, Any]) -> list[str]:
    names = []
    for image in _list(component.get("images")):
        name = _text(image) or _text(_map(image).get("name"))
        if name:
            names.append(name)
    return names


def _actions(component: dict[str, Any]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Commands that run when deploying or removing, and those that ran when the package was
    created."""
    host: list[dict[str, object]] = []
    created: list[dict[str, object]] = []
    for event, actions in _map(component.get("actions")).items():
        for stage, items in _map(actions).items():
            for item in _list(items):
                command = _text(_map(item).get("cmd"))
                if command is None:
                    continue
                entry: dict[str, object] = {
                    "component": str(component.get("name")),
                    "event": str(event),
                    "stage": str(stage),
                    "cmd": command[:500],
                }
                description = _text(_map(item).get("description"))
                if description:
                    entry["description"] = description[:200]
                if event in ("onDeploy", "onRemove"):
                    host.append(entry)
                elif event == "onCreate":
                    created.append(entry)
    return host, created


def _recorded_checksum(entry: dict[str, Any]) -> str | None:
    """The sha256 a component file entry records: ``shasum`` (v1alpha1) or ``checksum``."""
    value = _text(entry.get("shasum")) or _text(entry.get("checksum"))
    if value is None:
        return None
    algorithm, _, digest = value.rpartition(":")
    digest = digest.lower()
    if algorithm not in ("", "sha256") or not _HEX.match(digest):
        return None
    return digest


# --- the handler ----------------------------------------------------------------------------------


@dataclass
class _Package:
    view: ArtifactView
    ctx: Context
    contents: _Contents
    definition: dict[str, Any]
    # other copies of zarf.yaml in the same package: their components are checked too
    other_definitions: list[dict[str, Any]] = field(default_factory=list)
    findings_subject: Subject = field(init=False)
    missing: list[str] = field(default_factory=list)
    verifications: dict[ArtifactRef, tuple[Verification, ...]] = field(default_factory=dict)
    summary: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.findings_subject = Subject.of_artifact(self.view.ref)

    def ref(self, name: str) -> ArtifactRef:
        _, issue = check_member_name(name)
        return self.view.ref.child(name, unsafe=issue is not None)

    @property
    def build(self) -> dict[str, Any]:
        return _map(self.definition.get("build"))

    @property
    def metadata(self) -> dict[str, Any]:
        return _map(self.definition.get("metadata"))

    @property
    def components(self) -> list[dict[str, Any]]:
        """The components of every copy of zarf.yaml: which one Zarf would use is unknowable."""
        return [
            c
            for definition in (self.definition, *self.other_definitions)
            for c in _list(definition.get("components"))
            if isinstance(c, dict)
        ]

    @property
    def differential(self) -> dict[str, object] | None:
        flag = self.build.get("differential")
        if not flag:
            return None
        candidates = [self.build.get("differentialPackageVersion")]
        if isinstance(flag, dict):  # v1beta1
            candidates[:0] = [flag.get("fromVersion"), flag.get("packageVersion")]
        base = next((str(v)[:80] for v in candidates if isinstance(v, str | int) and str(v)), None)
        missing = [str(m) for m in _list(self.build.get("differentialMissing"))]
        return {"base": base, "missingComponents": missing}

    # 1. the checksum chain -------------------------------------------------------------------

    def checksums(self) -> tuple[bool, set[str]]:
        """Whether the chain from ``zarf.yaml`` to every listed file holds, and the files it
        vouches for."""
        recorder, contents = self.ctx.recorder, self.contents
        mismatched: list[dict[str, object]] = []
        aggregate = _text(self.metadata.get("aggregateChecksum")) or _text(
            self.build.get("aggregateChecksum")
        )
        listing = contents.control.get("checksums.txt")
        if listing is None:
            if "checksums.txt" in contents.oversized:
                recorder.not_assessed(
                    ("zarf.package.checksum-mismatch", "zarf.package.unlisted"),
                    self.findings_subject,
                    tool=TOOL,
                    reason="checksums.txt is too large to read",
                )
                return False, set()
            if aggregate:  # the definition says there is a checksum list; there is not
                self.missing.append("checksums.txt")
            recorder.not_assessed(
                ("zarf.package.checksum-mismatch", "zarf.package.unlisted"),
                self.findings_subject,
                tool=TOOL,
                reason="the package has no checksums.txt",
            )
            return False, set()
        actual_aggregate = hashlib.sha256(listing).hexdigest()
        bound = aggregate is not None and aggregate.lower() == actual_aggregate
        if aggregate is not None and not bound:
            mismatched.append(
                {"file": "checksums.txt", "expected": aggregate, "actual": actual_aggregate}
            )
        listed: dict[str, str] = {}
        malformed = 0
        for line in listing.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            digest, _, name = line.strip().partition(" ")
            name, _ = check_member_name(name.strip())
            if not _HEX.match(digest.lower()) or not name:
                malformed += 1
                continue
            listed[name] = digest.lower()
        vouched: set[str] = set()
        for name, digest in sorted(listed.items()):
            if name not in contents.digests:
                self.missing.append(name)
                continue
            seen = [contents.digests[name], *contents.duplicates.get(name, [])]
            if any(actual != digest for actual in seen):
                mismatched.append(
                    {
                        "file": name,
                        "expected": digest,
                        "actual": next(a for a in seen if a != digest),
                    }
                )
            else:
                vouched.add(name)
        if mismatched:
            recorder.fail(
                "zarf.package.checksum-mismatch",
                self.findings_subject,
                tool=TOOL,
                detail={"files": mismatched[:50], "count": len(mismatched)},
            )
        else:
            recorder.passed("zarf.package.checksum-mismatch", max(len(vouched), 1))
        provenance = _PROVENANCE | {
            n for p in _list(self.build.get("provenanceFiles")) if (n := _text(p))
        }
        unlisted = sorted(set(contents.digests) - set(listed) - provenance)
        if unlisted:
            recorder.fail(
                "zarf.package.unlisted",
                self.findings_subject,
                tool=TOOL,
                detail={"files": unlisted[:50], "count": len(unlisted)},
            )
        else:
            recorder.passed("zarf.package.unlisted", max(len(contents.digests), 1))
        self.summary["checksums"] = {
            "listed": len(listed),
            "matched": len(vouched),
            "malformedLines": malformed,
            "aggregate": "matches" if bound else ("absent" if aggregate is None else "differs"),
        }
        return bound and not mismatched, vouched | ({"checksums.txt"} if bound else set())

    # 2. the signature ------------------------------------------------------------------------

    def signature(self) -> Outcome | None:
        recorder = self.ctx.recorder
        definition = self.contents.control["zarf.yaml"]
        data = self.contents.control.get("zarf.bundle.sig")
        subject = Subject.of_artifact(self.ref("zarf.bundle.sig"))
        if data is None:
            if self.build.get("signed") is True:
                recorder.passed("upstream.signature.invalid")
                recorder.fail(
                    "upstream.signature.untrusted",
                    self.findings_subject,
                    tool=TOOL,
                    detail={
                        "status": "missing",
                        "reasons": [
                            "zarf.yaml says the package is signed, but it has no zarf.bundle.sig"
                        ],
                    },
                    attributes={"status": "missing", "method": "none"},
                )
                self.summary["signature"] = {"status": "missing"}
            else:
                self.summary["signature"] = {"status": "unsigned"}
            return None
        try:
            bundle = parse_bundle(data, artifact=definition)
        except DigestMismatch as exc:
            outcome = Outcome("invalid", "unknown", reasons=[str(exc)])
        except BundleError as exc:
            outcome = Outcome("unverifiable", "unknown", reasons=[f"unreadable bundle: {exc}"])
        else:
            outcome = verify_bundle(bundle, self.ctx, SCOPE, "Zarf packages")
        detail: dict[str, object] = {
            "method": outcome.method,
            "status": outcome.status,
            "signer": outcome.signer,
            "anchor": outcome.anchor,
            "reasons": list(outcome.reasons),
        }
        if outcome.status == "invalid":
            recorder.fail("upstream.signature.invalid", subject, tool=TOOL, detail=detail)
        else:
            recorder.passed("upstream.signature.invalid")
        if outcome.status in ("untrusted", "unverifiable"):
            recorder.fail(
                "upstream.signature.untrusted",
                subject,
                tool=TOOL,
                detail=detail,
                attributes={"status": outcome.status, "method": outcome.method},
            )
        elif outcome.status == "verified":
            recorder.passed("upstream.signature.untrusted")
        self.summary["signature"] = detail
        return outcome

    # 3. images -------------------------------------------------------------------------------

    def images(self) -> tuple[Inspection | None, list[str]]:
        """The image checks over ``images/``, and the images components name that it lacks."""
        contents = self.contents
        store = MemoryStore(
            {
                k.removeprefix("images/"): v
                for k, v in contents.digests.items()
                if k.startswith("images/")
            },
            {
                k.removeprefix("images/"): v
                for k, v in contents.sizes.items()
                if k.startswith("images/")
            },
            contents.documents,
        )
        named = sorted({n for c in self.components for n in _image_names(c)})
        inspection: Inspection | None = None
        present: set[str] = set()
        if store.exists("index.json"):
            index_ref = self.ref("images/index.json")
            index = BytesView(
                index_ref, contents.documents.get("index.json", b""), store.sha256("index.json")
            )
            try:
                inspection = inspect_store(
                    store, self.ctx, index, "container.image.oci-layout", root=index_ref
                )
                document = store.json("index.json")
            except (ValueError, KeyError, TypeError, RecursionError) as exc:
                self.ctx.recorder.not_assessed(
                    ("container.image.incomplete", "container.layer.digest-mismatch"),
                    Subject.of_artifact(index_ref),
                    tool=TOOL,
                    reason=f"the image index cannot be read: {str(exc)[:200]}",
                )
                document = {}
            for descriptor in _list(_map(document).get("manifests")):
                annotations = _map(_map(descriptor).get("annotations"))
                for key in ("org.opencontainers.image.ref.name", "io.containerd.image.name"):
                    if reference := _text(annotations.get(key)):
                        present.add(normalise_image(reference))
        absent = []
        for name in named:
            full = normalise_image(name)
            if full not in present and full.split("@", 1)[0] not in present:
                absent.append(name)
        self.summary["images"] = named
        return inspection, absent

    # 4. component files, actions --------------------------------------------------------------

    def component_files(self) -> tuple[list[dict[str, object]], list[str], int]:
        """(files placed on the host, component files that are missing, files checked)."""
        mismatched: list[dict[str, object]] = []
        host: list[dict[str, object]] = []
        missing: list[str] = []
        checked = 0
        for component in self.components:
            name = str(component.get("name"))
            tar = f"components/{name}.tar"
            files = self.contents.components.get(tar)
            for index, entry in enumerate(_list(component.get("files"))):
                entry = _map(entry)
                target = _text(entry.get("target")) or _text(entry.get("destination")) or ""
                if target and not target.startswith(_TEMP):
                    host.append(
                        {
                            "component": name,
                            "target": target[:300],
                            "executable": entry.get("executable") is True,
                            "symlinks": [str(s)[:300] for s in _list(entry.get("symlinks"))][:20],
                        }
                    )
                if files is None:
                    if tar not in self.contents.unreadable_components:
                        missing.append(f"{tar} (files of component {name})")
                    continue
                prefix = f"{name}/files/{index}/"
                stored = {k: v for k, v in files.items() if k.startswith(prefix)}
                if not stored:
                    missing.append(f"{tar}: {prefix}")
                    continue
                recorded = _recorded_checksum(entry)
                if recorded is None or entry.get("extractPath") or len(stored) != 1:
                    continue  # nothing recorded, or the checksum is of an archive or directory
                checked += 1
                [(path, (actual, _, _))] = stored.items()
                if actual != recorded:
                    mismatched.append(
                        {"file": f"{tar}: {path}", "expected": recorded, "actual": actual}
                    )
        for component in self.components:
            name = str(component.get("name"))
            tar = f"components/{name}.tar"
            expected = _declared_content(component, name)
            files = self.contents.components.get(tar)
            if not expected or tar in self.contents.unreadable_components:
                continue
            if files is None:
                if not _list(component.get("files")):  # already reported with its files
                    missing.append(f"{tar} (charts, manifests, repositories or data)")
                continue
            for label, prefix, suffix in expected:
                if not any(p.startswith(prefix) and p.endswith(suffix) for p in files):
                    missing.append(f"{tar}: {label}")
        if mismatched:
            self.ctx.recorder.fail(
                "zarf.package.checksum-mismatch",
                self.findings_subject,
                tool=TOOL,
                detail={"componentFiles": mismatched[:50]},
                discriminator="component-files",
            )
        unreadable = self.contents.unreadable_components
        if unreadable:
            self.ctx.recorder.not_assessed(
                ("zarf.package.checksum-mismatch",),
                self.findings_subject,
                tool=TOOL,
                reason="component tars that cannot be read: "
                + "; ".join(f"{k}: {v}" for k, v in sorted(unreadable.items()))[:500],
            )
        return host, missing, checked


def _declared_content(component: dict[str, Any], name: str) -> list[tuple[str, str, str]]:
    """(label, path prefix, path suffix) of what a component's tar must hold besides its files.

    Paths as Zarf writes them, checked against Zarf 1.0.1's init package (doc 35):
    ``<c>/charts/<chart>-<version>.tgz``, ``<c>/values/<chart>-<version>-<n>``,
    ``<c>/manifests/<manifest>-<n>.yaml`` (``kustomization-<manifest>-<n>.yaml``),
    ``<c>/repos/...`` and ``<c>/data/<n>/...``. Without a version, any version matches.
    """
    out: list[tuple[str, str, str]] = []
    for chart in _list(component.get("charts")):
        chart = _map(chart)
        chart_name = _text(chart.get("name"))
        if not chart_name:
            continue
        version = next(
            (
                str(v)
                for v in (
                    chart.get("version"),
                    _map(chart.get("helm")).get("version"),
                    _map(chart.get("oci")).get("version"),
                )
                if isinstance(v, str | int) and str(v)
            ),
            None,
        )
        stem = f"{chart_name}-{version}" if version else f"{chart_name}-"
        out.append((f"chart {chart_name} {version or ''}".strip(), f"{name}/charts/{stem}", ".tgz"))
        for index, _ in enumerate(_list(chart.get("valuesFiles"))):
            out.append(
                (
                    f"values file {index} of chart {chart_name}",
                    f"{name}/values/{stem}",
                    f"-{index}",
                )
            )
    for manifest in _list(component.get("manifests")):
        manifest = _map(manifest)
        manifest_name = _text(manifest.get("name"))
        if not manifest_name:
            continue
        for index, _ in enumerate(_list(manifest.get("files"))):
            path = f"{name}/manifests/{manifest_name}-{index}.yaml"
            out.append((f"manifest {manifest_name} file {index}", path, ""))
        for index, _ in enumerate(_list(manifest.get("kustomizations"))):
            path = f"{name}/manifests/kustomization-{manifest_name}-{index}.yaml"
            out.append((f"manifest {manifest_name} kustomization {index}", path, ""))
    if _list(component.get("repos")) or _list(component.get("repositories")):
        out.append(("git repositories", f"{name}/repos/", ""))
    for index, _ in enumerate(_list(component.get("dataInjections"))):
        out.append((f"data injection {index}", f"{name}/data/{index}/", ""))
    return out


def _unit_claims(package: _Package, summary: dict[str, object]) -> tuple[UnitClaim, ...]:
    root = package.view.ref
    claims = [
        UnitClaim(
            UnitKind.ZARF_PACKAGE,
            root,
            "package",
            root,
            package.view.sha256,
            {key: jsonable(value) for key, value in summary.items()},
        )
    ]
    roles = {
        "zarf.yaml": "definition",
        "checksums.txt": "checksums",
        "zarf.bundle.sig": "signature",
    }
    for name, sha in sorted(package.contents.digests.items()):
        role = roles.get(name)
        if role is None and name.startswith("components/"):
            role = "component"
        elif role is None and name == "images/index.json":
            role = "image-index"
        elif role is None and name.endswith(".tar") and "/" not in name:
            role = name.removesuffix(".tar")  # sboms, documentation
        if role:
            claims.append(UnitClaim(UnitKind.ZARF_PACKAGE, root, role, package.ref(name), sha))
    return tuple(claims)


class ZarfPackageHandler:
    name = "zarf"
    version = "1"
    kinds = frozenset({KIND})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if not _NAME.match(name_of(artifact.ref)):
            return None
        if detect_format(artifact.head(512)) in ("zstd", "tar"):
            return Detection(KIND, 85)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        subject = Subject.of_artifact(artifact.ref)
        if detect_format(artifact.head(512)) == "zstd" and not ZSTD:
            ctx.recorder.not_assessed(RULES, subject, tool=TOOL, reason=ZSTD_ADVICE)
            return Inspection(kind=KIND, metadata={"zarf": {"readable": False}})
        try:
            with _open(artifact, ctx) as stream:
                contents = _read(stream)
        except ARCHIVE_ERRORS as exc:
            ctx.recorder.not_assessed(
                RULES,
                subject,
                tool=TOOL,
                reason=f"the package cannot be read: {type(exc).__name__}: {str(exc)[:200]}",
            )
            return Inspection(kind=KIND, metadata={"zarf": {"readable": False}})
        if "zarf.yaml" not in contents.digests:
            return Inspection(kind="unclassified")  # named like a Zarf package, but is not one
        definition_bytes = contents.control.get("zarf.yaml")
        try:
            if definition_bytes is None:
                raise ValueError("zarf.yaml is too large to read")
            definition = load_untrusted_yaml(definition_bytes.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            ctx.recorder.not_assessed(
                RULES, subject, tool=TOOL, reason=f"zarf.yaml cannot be read: {str(exc)[:200]}"
            )
            return Inspection(kind=KIND, metadata={"zarf": {"readable": False}})
        schema = _map(definition).get("apiVersion")
        if not isinstance(definition, dict) or schema not in SCHEMAS:
            ctx.recorder.not_assessed(
                RULES,
                subject,
                tool=TOOL,
                reason=f"unknown Zarf package schema {str(schema)[:80]}",
            )
            return Inspection(kind=KIND, metadata={"zarf": {"schema": str(schema)[:80]}})
        others = []
        for copy in contents.control_copies.get("zarf.yaml", []):
            try:
                other = load_untrusted_yaml(copy.decode("utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError, ValueError, RecursionError):
                continue  # the conflict itself is reported; an unreadable copy adds nothing
            if isinstance(other, dict):
                others.append(other)
        return _check(_Package(artifact, ctx, contents, definition, others))


def _check(package: _Package) -> Inspection:
    ctx, subject = package.ctx, package.findings_subject
    recorder = ctx.recorder
    contents = package.contents
    later = {
        name: [s for s in shas if s != contents.digests[name]]
        for name, shas in contents.duplicates.items()
    }
    conflicted = report_conflicts(ctx, subject, contents.digests, later, TOOL)
    chained, vouched = package.checksums()
    outcome = package.signature()
    inspection, absent_images = package.images()
    host_files, missing_files, checked = package.component_files()
    differential = package.differential

    missing = [*package.missing, *missing_files]
    if not differential:
        missing += [f"image {name}" for name in absent_images]
    elif absent_images:
        recorder.not_assessed(
            ("zarf.package.incomplete",),
            Subject.of_artifact(package.view.ref, locator="images"),
            tool=TOOL,
            reason=f"a differential package leaves out the images of its base "
            f"({differential.get('base') or 'unknown version'})",
        )
    if missing:
        recorder.fail(
            "zarf.package.incomplete",
            subject,
            tool=TOOL,
            detail={"missing": missing[:50], "count": len(missing)},
        )
    else:
        recorder.passed("zarf.package.incomplete")

    host_actions: list[dict[str, object]] = []
    created: list[dict[str, object]] = []
    for component in package.components:
        deploy, create = _actions(component)
        host_actions += deploy
        created += create
    if host_actions:
        recorder.fail(
            "zarf.component.actions",
            subject,
            tool=TOOL,
            detail={"actions": host_actions[:100], "count": len(host_actions)},
        )
    else:
        recorder.passed("zarf.component.actions")
    if host_files:
        recorder.fail(
            "zarf.component.host-files",
            subject,
            tool=TOOL,
            detail={"files": host_files[:100], "count": len(host_files)},
        )
    else:
        recorder.passed("zarf.component.host-files")
    if differential:
        recorder.fail("zarf.package.differential", subject, tool=TOOL, detail=differential)
    else:
        recorder.passed("zarf.package.differential")

    # Trust: a verified signature over zarf.yaml reaches every file the checksum chain binds.
    verified = outcome is not None and outcome.status == "verified" and not conflicted
    if conflicted:
        chained = False  # which copy the signature and checksums vouch for cannot be told
    if verified and outcome is not None:
        signed = Verification(
            outcome.method, TrustLevel.SIGNATURE, Result.PASS, outcome.signer, outcome.anchor
        )
        package.verifications[package.ref("zarf.yaml")] = (signed,)
    if chained:
        level = TrustLevel.SIGNATURE if verified else TrustLevel.CHECKSUM
        via = Verification(
            "zarf-checksums",
            level,
            Result.PASS,
            outcome.signer if verified and outcome else None,
            outcome.anchor if verified and outcome else None,
            {"via": "zarf.yaml aggregateChecksum and checksums.txt"},
        )
        for name in sorted(vouched):
            package.verifications[package.ref(name)] = (via,)
        # The package file itself, so that trust.minimum can require it ("zarf.package":
        # signature): the chain reaches every listed member, the signature the definition.
        package.verifications[package.view.ref] = (via,)

    meta, build = package.metadata, package.build
    summary: dict[str, object] = {
        "name": _text(meta.get("name")),
        "version": _text(meta.get("version")),
        "kind": _text(package.definition.get("kind")),
        "architecture": _text(meta.get("architecture")) or _text(build.get("architecture")),
        "schema": _text(package.definition.get("apiVersion")) or "zarf.dev/v1alpha1",
        "builtWith": _text(build.get("version")),
        "componentNames": [str(c.get("name")) for c in package.components],
        "components": [_component_summary(c) for c in package.components],
        "checksums": package.summary.get("checksums"),
        "signature": package.summary.get("signature"),
        "images": package.summary.get("images"),
        "hostFiles": host_files[:100],
        "hostActions": len(host_actions),
        "createActions": created[:50],
        "componentFilesChecked": checked,
        "differential": differential,
        "sboms": "sboms.tar" in package.contents.digests,
    }
    claims = _unit_claims(package, summary)
    metadata: dict[str, object] = {"zarf": summary}
    if inspection is not None:
        claims = (*claims, *inspection.claims)
        metadata.update(inspection.metadata)
    return Inspection(
        kind=KIND, metadata=metadata, claims=claims, verifications=package.verifications
    )


def _component_summary(component: dict[str, Any]) -> dict[str, object]:
    charts = [
        f"{_text(_map(c).get('name')) or '?'} {_text(_map(c).get('version')) or ''}".strip()
        for c in _list(component.get("charts"))
    ]
    manifests = [str(_map(m).get("name")) for m in _list(component.get("manifests"))]
    repositories = [
        str(r if isinstance(r, str) else _map(r).get("url"))[:300]
        for r in _list(component.get("repos")) + _list(component.get("repositories"))
    ]
    return {
        "name": str(component.get("name")),
        "required": component.get("required") is True,
        "images": _image_names(component),
        "charts": charts,
        "manifests": manifests,
        "repositories": repositories,
        "files": len(_list(component.get("files"))),
        # files Zarf copies into running pods at deploy time, past the image review
        "dataInjections": [_injection(d) for d in _list(component.get("dataInjections"))][:50],
    }


def _injection(entry: object) -> dict[str, object]:
    target = _map(_map(entry).get("target"))
    return {
        "source": str(_map(entry).get("source") or "")[:300],
        "namespace": str(target.get("namespace") or "")[:100],
        "selector": str(target.get("selector") or "")[:200],
        "container": str(target.get("container") or "")[:100],
        "path": str(target.get("path") or "")[:300],
    }
