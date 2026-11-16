"""Package repository mirrors: dnf/yum, apt, PyPI simple, npm registry storage and Helm.

A mirror is a chain. For dnf and apt, a signed top file (``repomd.xml`` with ``repomd.xml.asc``;
``InRelease``, or ``Release`` with ``Release.gpg``) lists the hash of each index, and each index
(``primary.xml``, ``Packages``) lists the hash of each package. This handler checks each link
where it is found:

* metadata: its signature against keys pinned for ``repo.dnf`` or ``repo.apt``; every index it
  lists that is in the delivery against the listed hash (``repo.metadata.digest-mismatch``,
  final); ``Valid-Until``;
* indexes: every listed package that is in the delivery against the listed hash
  (``repo.content.digest-mismatch``, final).

PyPI simple pages, npm packuments and Helm ``index.yaml`` are indexes without signed metadata;
their hashes are checked the same way. A Helm ``.prov`` file is a clear-signed statement of a
chart's hash, checked against keys pinned for ``chart.helm``.

The repo-mirror assembler joins the links (doc 28): which indexes the verified metadata vouches
for, which packages those indexes vouch for, what is listed but missing, and freshness.
"""

import base64
import hashlib
import io
import posixpath
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from datetime import UTC, datetime

import yaml

from airlock import __version__
from airlock.archive import ARCHIVE_ERRORS
from airlock.core.canonical import JSON
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import (
    ArtifactRef,
    Result,
    Subject,
    ToolRef,
    TrustLevel,
    UnitClaim,
    UnitKind,
    Verification,
)
from airlock.core.serde import format_timestamp
from airlock.core.yamlio import load_untrusted_yaml
from airlock.formats import openpgp
from airlock.formats import repo as fmt
from airlock.handlers.common import (
    TooLarge,
    ancestor,
    full_path,
    name_of,
    parent_of,
    read_bytes,
    read_json,
    relative_to,
)
from airlock.trust import gpg_keys, signature_verification, verify_gpg

TOOL = ToolRef("airlock.mirrors", __version__)
KIND = UnitKind.REPO_MIRROR
_PRIMARY = re.compile(r"(^|-)primary\.xml(\.(gz|xz|bz2|zst))?$")
_PACKAGES = re.compile(r"^Packages(\.(gz|xz|bz2))?$")
_PACKAGES_ORDER = ("Packages.xz", "Packages.gz", "Packages", "Packages.bz2")
_METADATA_LIMIT = 64 << 20
_SAMPLE = 50


def _root_of(kind: str, ref: ArtifactRef) -> ArtifactRef:
    """The mirror's top directory: above ``repodata/``, ``dists/``, ``simple/`` or the packages."""
    parts = full_path(ref).split("/")
    if kind in ("repo.apt.release", "repo.apt.packages"):
        dists = len(parts) - 1 - parts[::-1].index("dists")
        return ancestor(ref, len(parts) - dists)
    if kind == "repo.npm.packument":
        scoped = len(parts) >= 3 and parts[-3].startswith("@")
        return ancestor(ref, 3 if scoped else 2)
    if kind in ("repo.dnf.repomd", "repo.dnf.primary"):
        return ancestor(ref, 2)
    if kind == "repo.pypi.simple":
        return ancestor(ref, 3)
    return parent_of(ref)


def _kind(view: ArtifactView) -> str | None:
    path = full_path(view.ref)
    name = name_of(view.ref)
    parts = path.split("/")
    if path.endswith("repodata/repomd.xml") or path == "repodata/repomd.xml":
        return "repo.dnf.repomd"
    if len(parts) >= 2 and parts[-2] == "repodata" and _PRIMARY.search(name):
        return "repo.dnf.primary"
    if "dists" in parts[:-1]:
        below = parts[parts.index("dists") + 1 :]
        if name in ("InRelease", "Release") and len(below) == 2:
            return "repo.apt.release"
        if _PACKAGES.match(name) and len(below) >= 4 and below[-2].startswith("binary-"):
            return "repo.apt.packages"
    if len(parts) >= 3 and parts[-3] == "simple" and name in ("index.html", "index.json"):
        return "repo.pypi.simple"
    if name == "package.json":
        head = view.head(1 << 16)
        if (
            head.lstrip().startswith(b"{")
            and b'"versions"' in head
            and (b'"dist-tags"' in head or b'"_id"' in head)
        ):
            return "repo.npm.packument"
    if name == "index.yaml" and b"entries:" in view.head(1 << 16):
        return "repo.helm.index"
    if name.endswith(".tgz.prov"):
        return "repo.helm.provenance"
    return None


def _hex(view: ArtifactView, algorithm: str) -> str | None:
    if algorithm == "sha256" and view.sha256:
        return view.sha256
    if algorithm not in hashlib.algorithms_available:
        return None
    digest = hashlib.new(algorithm, usedforsecurity=False)
    with view.open() as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def _matches(view: ArtifactView, listed: fmt.Listed) -> bool | None:
    """Whether ``view`` has the listed hash; None if there is no hash to compare."""
    if not listed.algorithm or not listed.digest:
        return None
    actual = _hex(view, listed.algorithm)
    if actual is None:
        return None
    if re.fullmatch(r"[0-9a-f]+", listed.digest):
        return actual == listed.digest
    return base64.b64encode(bytes.fromhex(actual)).decode() == listed.digest  # SRI (npm)


class _Index:
    """Checks the entries of one index against the delivery and makes the claims."""

    def __init__(self, view: ArtifactView, ctx: Context, fmt_name: str, root: ArtifactRef) -> None:
        self.view, self.ctx, self.format, self.root = view, ctx, fmt_name, root
        self.position = relative_to(view.ref, root) or name_of(view.ref)
        self.listed = self.present = self.external = self.mismatched = 0
        self.missing: list[JSON] = []
        self.claims: list[UnitClaim] = []

    def check(self, entries: Iterable[fmt.Listed], base: str, rule: str) -> None:
        """``base``: where hrefs start, relative to this index's directory."""
        for entry in entries:
            self.listed += 1
            if entry.external:
                self.external += 1
                continue
            target = self.view.resolve(posixpath.join(base, entry.href))
            if target is None:
                if len(self.missing) < _SAMPLE:
                    self.missing.append(entry.href)
                continue
            self.present += 1
            match = _matches(target, entry)
            if match is False:
                self.mismatched += 1
                self.ctx.recorder.fail(
                    rule,
                    Subject.of_artifact(target.ref),
                    tool=TOOL,
                    detail={
                        "index": self.view.ref.display,
                        "algorithm": entry.algorithm,
                        "listed": entry.digest,
                    },
                )
            self.claims.append(
                UnitClaim(
                    kind=KIND,
                    root=self.root,
                    role="content" if rule == "repo.content.digest-mismatch" else "listed-index",
                    artifact=target.ref,
                    sha256=target.sha256,
                    facts={
                        "index": self.position,
                        "path": relative_to(target.ref, self.root),
                        # MD5 can show a difference but proves nothing when it matches.
                        "hashed": match is True and entry.algorithm != "md5",
                        "mismatch": match is False,
                    },
                )
            )
        if not self.mismatched and self.present:
            self.ctx.recorder.passed(rule, self.present)

    def claim(self, role: str = "index", **facts: JSON) -> UnitClaim:
        return UnitClaim(
            kind=KIND,
            root=self.root,
            role=role,
            artifact=self.view.ref,
            sha256=self.view.sha256,
            facts={
                "format": self.format,
                "path": self.position,
                "listed": self.listed,
                "present": self.present,
                "external": self.external,
                "missing": self.listed - self.present - self.external,
                "missingSample": self.missing,
                **facts,
            },
        )

    def inspection(
        self,
        kind: str,
        role: str = "index",
        signed: tuple[openpgp.Result | None, str | None] = (None, None),
        **facts: JSON,
    ) -> Inspection:
        """``signed``: the metadata's own signature check, recorded on it when it verified."""
        claim = self.claim(role, **facts)
        summary = {k: v for k, v in claim.facts.items() if k != "missingSample"}
        result, anchor = signed
        verifications = (
            {self.view.ref: (signature_verification(result, anchor),)}
            if result is not None and result.valid
            else {}
        )
        return Inspection(
            kind=kind,
            metadata={"repoIndex": summary},
            claims=(claim, *self.claims),
            verifications=verifications,
        )


def _signature(
    view: ArtifactView, ctx: Context, scope: str, result: openpgp.Result | None, anchor: str | None
) -> dict[str, JSON]:
    """Record the metadata signature outcome; returns the facts for the claim."""
    subject = Subject.of_artifact(view.ref)
    if result is None:
        ctx.recorder.fail("repo.metadata.unsigned", subject, tool=TOOL, detail={"scope": scope})
        return {"signature": "unsigned"}
    ctx.recorder.passed("repo.metadata.unsigned")
    if result.valid:
        ctx.recorder.passed("repo.metadata.signature.invalid")
        ctx.recorder.passed("repo.metadata.signature.untrusted")
        return {
            "signature": "verified",
            "anchor": anchor,
            "signer": result.key.fingerprint if result.key else None,
        }
    if result.key is not None:
        ctx.recorder.fail(
            "repo.metadata.signature.invalid",
            subject,
            tool=TOOL,
            detail={"reason": result.reason, "key": result.key.fingerprint},
        )
        return {"signature": "invalid"}
    issuer = result.signature.issuer if result.signature else None
    ctx.recorder.fail(
        "repo.metadata.signature.untrusted",
        subject,
        tool=TOOL,
        detail={"reason": result.reason, "issuer": issuer, "scope": scope},
    )
    return {"signature": "untrusted", "issuer": issuer}


def _detached(
    view: ArtifactView, data: bytes, name: str, ctx: Context, scope: str
) -> tuple[openpgp.Result | None, str | None]:
    """(result, anchor) for a sibling detached signature, or (None, None) if there is none."""
    sibling = view.resolve(name)
    if sibling is None:
        return None, None
    try:
        signatures = openpgp.load_signatures(read_bytes(sibling, 1 << 20))
    except (openpgp.OpenPGPError, TooLarge, ValueError, IndexError) as exc:
        return openpgp.Result(False, reason=f"unreadable signature: {exc}"), None
    last: tuple[openpgp.Result | None, str | None] = (
        openpgp.Result(False, reason="no signature"),
        None,
    )
    for signature in signatures:  # InRelease and Release.gpg are often signed by two keys
        result, anchor = verify_gpg(ctx, scope, signature, [data])
        if result.valid:
            return result, anchor
        if last[0] is None or last[0].key is None:
            last = (result, anchor)
    return last


def _malformed(view: ArtifactView, ctx: Context, kind: str, error: object) -> Inspection:
    ctx.recorder.fail(
        "repo.metadata.malformed",
        Subject.of_artifact(view.ref),
        tool=TOOL,
        detail={"error": str(error)[:500]},
    )
    return Inspection(kind=kind, metadata={"repoIndex": {"error": str(error)[:500]}})


class MirrorHandler:
    name = "mirrors"
    version = "1"
    kinds = frozenset(
        {
            "repo.dnf.repomd",
            "repo.dnf.primary",
            "repo.apt.release",
            "repo.apt.packages",
            "repo.pypi.simple",
            "repo.npm.packument",
            "repo.helm.index",
            "repo.helm.provenance",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 80) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact)
        assert kind is not None  # noqa: S101 - only called after detect()
        if artifact.ref.nested:
            # A mirror packed into an archive: the files an index lists cannot be reached from
            # inside it, so the chain is not checked, and that is said rather than skipped.
            ctx.recorder.not_assessed(
                ("repo.metadata.digest-mismatch", "repo.content.digest-mismatch"),
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason="repository metadata inside an archive: deliver the mirror as a directory "
                "to have it checked against its packages",
            )
            return Inspection(kind=kind, metadata={"repoIndex": {"assessed": False}})
        root = _root_of(kind, artifact.ref)
        readers = {
            "repo.dnf.repomd": self._dnf_repomd,
            "repo.dnf.primary": self._dnf_primary,
            "repo.apt.release": self._apt_release,
            "repo.apt.packages": self._apt_packages,
            "repo.pypi.simple": self._pypi_simple,
            "repo.npm.packument": self._npm_packument,
            "repo.helm.index": self._helm_index,
            "repo.helm.provenance": self._helm_provenance,
        }
        try:
            return readers[kind](artifact, ctx, kind, root)
        except (fmt.RepoError, TooLarge, ET.ParseError, yaml.YAMLError, *ARCHIVE_ERRORS) as exc:
            return _malformed(artifact, ctx, kind, exc)

    # --- dnf ------------------------------------------------------------------------------------

    def _dnf_repomd(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        data = read_bytes(view, _METADATA_LIMIT)
        repomd = fmt.parse_repomd(data)
        result, anchor = _detached(view, data, "repomd.xml.asc", ctx, "repo.dnf")
        index = _Index(view, ctx, "dnf", root)
        index.check(repomd.data.values(), "..", "repo.metadata.digest-mismatch")
        snapshot = None
        if repomd.timestamp:
            snapshot = format_timestamp(datetime.fromtimestamp(repomd.timestamp, UTC))
        return index.inspection(
            kind,
            role="metadata",
            identity=f"dnf:{root.display}",
            snapshot=snapshot,
            revision=repomd.revision,
            indexes=[e.href for e in repomd.data.values()],
            signed=(result, anchor),
            **_signature(view, ctx, "repo.dnf", result, anchor),
        )

    def _dnf_primary(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        index = _Index(view, ctx, "dnf", root)
        with view.open() as raw, fmt.open_compressed(name_of(view.ref), raw) as stream:
            index.check(fmt.iter_primary(stream), "..", "repo.content.digest-mismatch")
        return index.inspection(kind)

    # --- apt ------------------------------------------------------------------------------------

    def _apt_release(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        data = read_bytes(view, _METADATA_LIMIT)
        if name_of(view.ref) == "InRelease":
            pinned = gpg_keys(ctx, "repo.apt")
            keys = [k for _, group in pinned for k in group]
            result, signed = openpgp.verify_clearsigned(data, keys)
            if not signed:
                raise fmt.RepoError("InRelease is not a clear-signed document")
            anchor = next((a.name for a, group in pinned if result.key in group), None)
            text = signed.decode("utf-8", "replace")
            outcome: openpgp.Result | None = result
        else:
            outcome, anchor = _detached(view, data, "Release.gpg", ctx, "repo.apt")
            text = data.decode("utf-8", "replace")
        release = fmt.parse_release(text)
        index = _Index(view, ctx, "apt", root)
        index.check(release.files.values(), ".", "repo.metadata.digest-mismatch")
        suite = relative_to(parent_of(view.ref), root) or ""
        if release.valid_until is not None and release.valid_until < ctx.now:
            ctx.recorder.fail(
                "repo.metadata.expired",
                Subject.of_artifact(view.ref),
                tool=TOOL,
                detail={"validUntil": format_timestamp(release.valid_until)},
            )
        elif release.valid_until is not None:
            ctx.recorder.passed("repo.metadata.expired")
        return index.inspection(
            kind,
            role="metadata",
            identity=f"apt:{release.identity}",
            snapshot=format_timestamp(release.date) if release.date else None,
            validUntil=format_timestamp(release.valid_until) if release.valid_until else None,
            suite=release.fields.get("Suite") or release.fields.get("Codename"),
            architectures=" ".join(release.fields.get("Architectures", "").split()),
            components=" ".join(release.fields.get("Components", "").split()),
            indexes=[posixpath.join(suite, p) for p in sorted(release.files)],
            signed=(outcome, anchor),
            **_signature(view, ctx, "repo.apt", outcome, anchor),
        )

    def _apt_packages(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        index = _Index(view, ctx, "apt", root)
        name = name_of(view.ref)
        preferred = next((n for n in _PACKAGES_ORDER if view.resolve(n) is not None), name)
        if preferred != name:  # the same index in another compression: read it once
            return index.inspection(kind, sameAs=preferred)
        depth = (relative_to(view.ref, root) or "").count("/")
        with view.open() as raw, fmt.open_compressed(name, raw) as stream:
            lines = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
            base = "/".join([".."] * depth) or "."
            index.check(fmt.iter_packages(lines), base, "repo.content.digest-mismatch")
        return index.inspection(kind)

    # --- PyPI, npm, Helm ------------------------------------------------------------------------

    def _pypi_simple(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        index = _Index(view, ctx, "pypi", root)
        index.check(
            fmt.parse_simple(read_bytes(view, _METADATA_LIMIT)), ".", "repo.content.digest-mismatch"
        )
        return index.inspection(kind, project=name_of(parent_of(view.ref)))

    def _npm_packument(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        document = read_json(view, _METADATA_LIMIT)
        if not fmt.is_packument(document):
            return Inspection(kind=kind, metadata={"repoIndex": {"packument": False}})
        index = _Index(view, ctx, "npm", root)
        index.check(fmt.iter_packument(document), ".", "repo.content.digest-mismatch")
        return index.inspection(kind, project=str(document.get("name")))

    def _helm_index(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        text = read_bytes(view, _METADATA_LIMIT).decode("utf-8", "replace")
        document = load_untrusted_yaml(text, aliases=True)
        helm = fmt.parse_helm_index(document)
        index = _Index(view, ctx, "helm", root)
        index.check(helm.charts, ".", "repo.content.digest-mismatch")
        return index.inspection(
            kind,
            role="metadata",
            identity=f"helm:{root.display}",
            snapshot=format_timestamp(helm.generated) if helm.generated else None,
            signature="not-applicable",
        )

    def _helm_provenance(
        self, view: ArtifactView, ctx: Context, kind: str, root: ArtifactRef
    ) -> Inspection:
        chart = view.resolve(name_of(view.ref).removesuffix(".prov"))
        data = read_bytes(view, 1 << 20)
        pinned = gpg_keys(ctx, "chart.helm")
        result, body = openpgp.verify_clearsigned(data, [k for _, ks in pinned for k in ks])
        anchor = next((a.name for a, group in pinned if result.key in group), None)
        listed = fmt.provenance_files(body.decode("utf-8", "replace"))
        subject = Subject.of_artifact(view.ref)
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        if chart is not None and name_of(chart.ref) in listed:
            if chart.sha256 != listed[name_of(chart.ref)]:
                ctx.recorder.fail(
                    "upstream.checksum-mismatch",
                    Subject.of_artifact(chart.ref),
                    tool=TOOL,
                    detail={
                        "list": name_of(view.ref),
                        "algorithm": "sha256",
                        "listed": listed[name_of(chart.ref)],
                    },
                )
            elif result.valid:
                verifications[chart.ref] = (signature_verification(result, anchor),)
            else:
                verifications[chart.ref] = (
                    Verification(
                        "helm-provenance",
                        TrustLevel.CHECKSUM,
                        Result.PASS,
                        anchor=name_of(view.ref),
                    ),
                )
        if result.valid:
            ctx.recorder.passed("upstream.signature.invalid")
        elif result.key is not None:
            ctx.recorder.fail(
                "upstream.signature.invalid", subject, tool=TOOL, detail={"reason": result.reason}
            )
        else:
            issuer = result.signature.issuer if result.signature else None
            ctx.recorder.fail(
                "upstream.signature.untrusted",
                subject,
                tool=TOOL,
                detail={"reason": result.reason, "issuer": issuer},
            )
        summary = {"chart": name_of(chart.ref) if chart else None, "verified": result.valid}
        return Inspection(
            kind=kind, metadata={"helmProvenance": summary}, verifications=verifications
        )
