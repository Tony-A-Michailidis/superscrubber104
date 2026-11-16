"""Publishers' checksum lists and detached signatures, for any file.

Vendors ship drivers, ISO images, cloud images, firmware, tools and Maven artifacts with
``SHA256SUMS`` (often signed: ``SHA256SUMS.gpg`` or a clear-signed ``CHECKSUM``), with a one-line
sidecar (``file.iso.sha256``, ``lib.jar.sha1``), or with a detached ``.asc``/``.sig``.

* Every file a checksum list names that is in the delivery is hashed and compared. A difference is
  ``upstream.checksum-mismatch`` and final: the file is not what its publisher listed.
* The list's own signature is verified against keys the policy pins for ``file.checksums``. A
  verified list gives its files a ``signature``-level verification; an unsigned list (or one whose
  signature cannot be tied to a pinned key) gives ``checksum`` level, since the list travelled
  with the content. MD5 lists can show a mismatch but earn no verification: MD5 proves nothing.
* A detached OpenPGP signature over a file is verified against keys pinned for ``file.signed``.

A signature can only add trust. One that does not verify with a pinned key is final
(``upstream.signature.invalid``); one that cannot be read, or is from a key nobody pinned, is
``upstream.signature.untrusted``. Lists and signatures inside archives cannot look up the files
beside them: that is recorded as not assessed.

Repository metadata signatures (``repomd.xml.asc``, ``Release.gpg``, ``InRelease``) are checked by
the mirror handler against repository keys, not here.
"""

import hashlib
import re
from collections.abc import Iterable, Iterator

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import ArtifactRef, Result, Subject, ToolRef, TrustLevel, Verification
from airlock.formats import openpgp
from airlock.handlers.common import TooLarge, name_of, read_bytes
from airlock.trust import gpg_keys, signature_verification, verify_gpg

TOOL = ToolRef("airlock.upstream", __version__)
_LIST_NAMES = re.compile(
    r"(?i)^((sha(1|224|256|384|512)|md5)sums?(\.txt)?|checksums?(\.txt)?|.*[-_.]checksum)$"
)
_SIDECARS = {
    ".sha512": "sha512",
    ".sha512sum": "sha512",
    ".sha256": "sha256",
    ".sha256sum": "sha256",
    ".sha1": "sha1",
    ".md5": "md5",
}
_GNU = re.compile(r"^(?P<hash>[0-9a-fA-F]{32,128})\s+\*?(?P<name>[^\r\n]+?)\s*$")
_BSD = re.compile(
    r"^(?P<algo>SHA1|SHA224|SHA256|SHA384|SHA512|MD5)\s*\((?P<name>[^)]+)\)\s*=\s*(?P<hash>[0-9a-fA-F]+)\s*$"
)
_BARE = re.compile(r"^[0-9a-fA-F]{32,128}$")
_BY_LENGTH = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
_REPO_SIGNATURES = frozenset({"repomd.xml.asc", "release.gpg", "inrelease"})
_SIGNATURE_SUFFIXES = (".gpg", ".asc", ".sig")
_LIMIT = 16 << 20


def _sidecar(name: str) -> tuple[str, str] | None:
    """(target name, algorithm) when ``name`` is ``<target>.sha256`` and the like."""
    lower = name.lower()
    for suffix, algorithm in _SIDECARS.items():
        if lower.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)], algorithm
    return None


def _entries(text: str, implied: str | None) -> Iterator[tuple[str, str, str]]:
    """(algorithm, hex, file name) for every line of a checksum list. ``implied`` is the file a
    sidecar is named after, for a line that holds a hash alone."""
    for raw in text.splitlines():
        line = raw.strip()
        if match := _BSD.match(line):
            yield match["algo"].lower(), match["hash"].lower(), match["name"].strip()
        elif match := _GNU.match(line):
            algorithm = _BY_LENGTH.get(len(match["hash"]))
            if algorithm:
                yield algorithm, match["hash"].lower(), match["name"].strip().removeprefix("./")
        elif implied and _BARE.match(line) and (algorithm := _BY_LENGTH.get(len(line))):
            yield algorithm, line.lower(), implied


def _digest(view: ArtifactView, algorithm: str) -> str | None:
    if algorithm == "sha256" and view.sha256:
        return view.sha256
    if algorithm not in hashlib.algorithms_available:
        return None
    digest = hashlib.new(algorithm, usedforsecurity=False)
    with view.open() as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def _is_signature(data: bytes) -> bool:
    return b"-----BEGIN PGP SIGNATURE-----" in data[:200] or (
        bool(data) and data[0] in (0x88, 0x89, 0x8A, 0xC2)
    )


def _looks_like_checksums(head: bytes) -> bool:
    first = head.decode("utf-8", "replace").strip().split("\n", 1)[0].strip()
    return bool(_BARE.match(first) or _GNU.match(first) or _BSD.match(first))


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref)
    lower = name.lower()
    if lower in _REPO_SIGNATURES:
        return None
    if _LIST_NAMES.match(name):
        return "upstream.checksum-list"
    if _sidecar(name) and view.size <= 4096 and _looks_like_checksums(view.head(256)):
        return "upstream.checksum-list"
    if lower.endswith(_SIGNATURE_SUFFIXES) and _is_signature(view.head(256)):
        stem = name.rsplit(".", 1)[0]
        if not _LIST_NAMES.match(stem) and not _sidecar(stem):
            return "upstream.signature"  # a list's signature is checked with the list
    return None


def _verify_any(
    ctx: Context, scope: str, signatures: Iterable[openpgp.Signature], chunks: list[bytes]
) -> tuple[openpgp.Result, str | None]:
    """Verify with any of the signatures (publishers often sign with two keys). The result that
    is kept on failure is the most telling one: a pinned key that did not verify."""
    best: tuple[openpgp.Result, str | None] = (
        openpgp.Result(False, reason="no signature found"),
        None,
    )
    for signature in signatures:
        result, anchor = verify_gpg(ctx, scope, signature, chunks)
        if result.valid:
            return result, anchor
        if best[0].key is None:
            best = (result, anchor)
    return best


def _record_signature(
    view: ArtifactView, result: openpgp.Result, anchor: str | None, ctx: Context
) -> Verification | None:
    """Record the outcome of a signature check; a verification only when it holds."""
    subject = Subject.of_artifact(view.ref)
    if result.valid:
        ctx.recorder.passed("upstream.signature.invalid")
        ctx.recorder.passed("upstream.signature.untrusted")
        return signature_verification(result, anchor)
    if result.key is not None:
        ctx.recorder.fail(
            "upstream.signature.invalid",
            subject,
            tool=TOOL,
            detail={"reason": result.reason, "key": result.key.fingerprint},
        )
    else:
        issuer = result.signature.issuer if result.signature else None
        ctx.recorder.fail(
            "upstream.signature.untrusted",
            subject,
            tool=TOOL,
            detail={"reason": result.reason, "issuer": issuer},
        )
    return None


def _unreadable(error: object) -> openpgp.Result:
    return openpgp.Result(False, reason=f"the signature cannot be read: {error}")


class UpstreamHandler:
    name = "upstream"
    version = "2"
    kinds = frozenset({"upstream.checksum-list", "upstream.signature"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 70) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact) or "upstream.signature"
        if artifact.ref.nested:
            # Inside an archive there is no way to reach the files beside this one.
            rules = (
                ("upstream.checksum-mismatch",)
                if kind == "upstream.checksum-list"
                else ("upstream.signature.invalid", "upstream.signature.untrusted")
            )
            ctx.recorder.not_assessed(
                rules,
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason="inside an archive: the files it covers cannot be looked up; deliver it "
                "unpacked to have it checked",
            )
            return Inspection(kind=kind, metadata={"upstream": {"assessed": False}})
        if kind == "upstream.checksum-list":
            return self._checksums(artifact, ctx)
        return self._detached(artifact, ctx)

    def _list_signature(
        self, view: ArtifactView, data: bytes, ctx: Context
    ) -> tuple[Verification | None, str, bool]:
        """How far the list itself can be trusted, its text, and whether it carries a
        signature at all."""
        if b"-----BEGIN PGP SIGNED MESSAGE-----" in data[:100]:
            pinned = gpg_keys(ctx, "file.checksums")
            result, signed = openpgp.verify_clearsigned(data, [k for _, ks in pinned for k in ks])
            anchor = next((a.name for a, ks in pinned if result.key in ks), None)
            # Only the signed text is read: anything outside it is not the publisher's.
            return (
                _record_signature(view, result, anchor, ctx),
                signed.decode("utf-8", "replace"),
                True,
            )
        text = data.decode("utf-8", "replace")
        for suffix in _SIGNATURE_SUFFIXES:
            sibling = view.resolve(name_of(view.ref) + suffix)
            if sibling is None:
                continue
            try:
                signatures = openpgp.load_signatures(read_bytes(sibling, 1 << 20))
                result, anchor = _verify_any(ctx, "file.checksums", signatures, [data])
            except (openpgp.OpenPGPError, TooLarge) as exc:
                result, anchor = _unreadable(exc), None
            return _record_signature(view, result, anchor, ctx), text, True
        return None, text, False

    def _checksums(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            data = read_bytes(view, _LIMIT)
        except TooLarge as exc:
            ctx.recorder.not_assessed(
                ("upstream.checksum-mismatch",),
                Subject.of_artifact(view.ref),
                tool=TOOL,
                reason=str(exc),
            )
            return Inspection(kind="upstream.checksum-list")
        signed, text, has_signature = self._list_signature(view, data, ctx)
        sidecar = _sidecar(name_of(view.ref))
        listed = checked = mismatched = 0
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        for algorithm, expected, name in _entries(text, sidecar[0] if sidecar else None):
            listed += 1
            target = view.resolve(name)
            if target is None or target.ref == view.ref:
                continue
            actual = _digest(target, algorithm)
            if actual is None:
                continue
            checked += 1
            if actual != expected:
                mismatched += 1
                ctx.recorder.fail(
                    "upstream.checksum-mismatch",
                    Subject.of_artifact(target.ref),
                    tool=TOOL,
                    detail={
                        "list": name_of(view.ref),
                        "algorithm": algorithm,
                        "listed": expected,
                        "actual": actual,
                    },
                )
            elif signed is not None:
                verifications[target.ref] = (signed,)
            elif algorithm != "md5":
                verifications[target.ref] = (
                    Verification(
                        "checksum-list",
                        TrustLevel.CHECKSUM,
                        Result.PASS,
                        anchor=name_of(view.ref),
                        detail={"algorithm": algorithm},
                    ),
                )
        if checked and not mismatched:
            ctx.recorder.passed("upstream.checksum-mismatch", checked)
        summary = {
            "listed": listed,
            "checked": checked,
            "signed": signed is not None,
            "signaturePresent": has_signature,
        }
        return Inspection(
            kind="upstream.checksum-list",
            metadata={"checksumList": summary},
            verifications=verifications,
        )

    def _detached(self, view: ArtifactView, ctx: Context) -> Inspection:
        target = view.resolve(name_of(view.ref).rsplit(".", 1)[0])
        if target is None:
            ctx.recorder.not_assessed(
                ("upstream.signature.invalid", "upstream.signature.untrusted"),
                Subject.of_artifact(view.ref),
                tool=TOOL,
                reason="the file this signature is for is not beside it",
            )
            return Inspection(kind="upstream.signature", metadata={"signature": {"target": None}})
        issuer = None
        try:
            signatures = openpgp.load_signatures(read_bytes(view, 1 << 20))
            issuer = signatures[0].issuer if signatures else None
            # Large files are hashed once per signature tried; publishers rarely use more than two.
            best: tuple[openpgp.Result, str | None] = (
                openpgp.Result(False, reason="no signature found"),
                None,
            )
            for signature in signatures:
                with target.open() as stream:
                    chunks = iter(lambda s=stream: s.read(1 << 20), b"")  # type: ignore[misc]
                    result, anchor = verify_gpg(ctx, "file.signed", signature, chunks)
                if result.valid or best[0].key is None:
                    best = (result, anchor)
                if result.valid:
                    break
            result, anchor = best
        except (openpgp.OpenPGPError, TooLarge) as exc:
            result, anchor = _unreadable(exc), None
        verification = _record_signature(view, result, anchor, ctx)
        summary = {"target": name_of(target.ref), "issuer": issuer, "verified": result.valid}
        return Inspection(
            kind="upstream.signature",
            metadata={"signature": summary},
            verifications={target.ref: (verification,)} if verification else {},
        )
