"""Publishers' checksum lists and detached signatures, for any file.

Vendors ship drivers, ISO images, cloud images, firmware and tools with ``SHA256SUMS`` (often
signed: ``SHA256SUMS.gpg`` or a clear-signed ``CHECKSUM``) or with a detached ``.asc``/``.sig``.

* Every file a checksum list names that is in the delivery is hashed and compared. A difference is
  ``upstream.checksum-mismatch`` and final: the file is not what its publisher listed.
* The list's own signature is verified against keys the policy pins for ``file.checksums``. A
  verified list gives its files a ``signature``-level verification; an unsigned (or unverifiable)
  list gives ``checksum`` level, since the list travelled with the content.
* A detached OpenPGP signature over a file is verified against keys pinned for ``file.signed``.

Repository metadata signatures (``repomd.xml.asc``, ``Release.gpg``, ``InRelease``) are checked by
the mirror assembler against repository keys, not here.
"""

import hashlib
import re
from collections.abc import Iterator

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import ArtifactRef, Result, Subject, ToolRef, TrustLevel, Verification
from airlock.formats import openpgp
from airlock.handlers.common import TooLarge, name_of, read_bytes
from airlock.trust import gpg_keys, signature_verification, verify_gpg

TOOL = ToolRef("airlock.upstream", __version__)
_LIST_NAMES = re.compile(
    r"(?i)^(sha(1|224|256|384|512)sums?(\.txt)?|checksums?(\.txt)?|.*[-_.]checksum|.*\.sha(256|512)(sum)?)$"
)
_GNU = re.compile(r"^(?P<hash>[0-9a-fA-F]{40,128})\s+\*?(?P<name>[^\r\n]+?)\s*$")
_BSD = re.compile(
    r"^(?P<algo>SHA1|SHA224|SHA256|SHA384|SHA512|MD5)\s*\((?P<name>[^)]+)\)\s*=\s*(?P<hash>[0-9a-fA-F]+)\s*$"
)
_BY_LENGTH = {40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
_REPO_SIGNATURES = frozenset({"repomd.xml.asc", "release.gpg", "inrelease"})
_LIMIT = 16 << 20


def _entries(text: str) -> Iterator[tuple[str, str, str]]:
    """(algorithm, hex, file name) for every line of a checksum list."""
    for line in text.splitlines():
        if match := _BSD.match(line.strip()):
            yield match["algo"].lower(), match["hash"].lower(), match["name"].strip()
        elif match := _GNU.match(line.strip()):
            algorithm = _BY_LENGTH.get(len(match["hash"]))
            if algorithm:
                yield algorithm, match["hash"].lower(), match["name"].strip().lstrip("./")


def _digest(view: ArtifactView, algorithm: str) -> str | None:
    if algorithm == "sha256" and view.sha256:
        return view.sha256
    if algorithm not in hashlib.algorithms_available:
        return None
    digest = hashlib.new(algorithm)
    with view.open() as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def _signature_kind(data: bytes) -> bool:
    return b"-----BEGIN PGP SIGNATURE-----" in data[:200] or (
        bool(data) and data[0] & 0x80 == 0x80 and data[0] in (0x88, 0x89, 0x8A, 0xC2)
    )


class UpstreamHandler:
    name = "upstream"
    version = "1"
    kinds = frozenset({"upstream.checksum-list", "upstream.signature"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        name = name_of(artifact.ref)
        if name.lower() in _REPO_SIGNATURES:
            return None
        if _LIST_NAMES.match(name):
            return Detection("upstream.checksum-list", 70)
        if name.lower().endswith((".asc", ".sig", ".gpg")) and _signature_kind(artifact.head(256)):
            stem = name.rsplit(".", 1)[0]
            if not _LIST_NAMES.match(stem):  # a list's signature is checked with the list
                return Detection("upstream.signature", 70)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        detection = self.detect(artifact)
        assert detection is not None  # noqa: S101 - only called after detect()
        if detection.kind == "upstream.checksum-list":
            return self._checksums(artifact, ctx)
        return self._detached(artifact, ctx)

    def _list_signature(
        self, view: ArtifactView, data: bytes, ctx: Context
    ) -> tuple[Verification | None, str]:
        """How far the list itself can be trusted, and its text."""
        if b"-----BEGIN PGP SIGNED MESSAGE-----" in data[:100]:
            signatures = openpgp.load_signatures(
                data[data.find(b"-----BEGIN PGP SIGNATURE-----") :]
            )
            pinned = gpg_keys(ctx, "file.checksums")
            result, signed_text = openpgp.verify_clearsigned(
                data, [k for _, ks in pinned for k in ks]
            )
            body = signed_text.decode("utf-8", "replace")
            if result.valid:
                anchor = next((a.name for a, ks in pinned if result.key in ks), None)
                return signature_verification(result, anchor), body
            self._signature_finding(view, result, ctx, signatures[0].issuer if signatures else None)
            return None, body
        text = data.decode("utf-8", "replace")
        for suffix in (".gpg", ".asc", ".sig"):
            sibling = view.resolve(name_of(view.ref) + suffix)
            if sibling is None:
                continue
            try:
                signature = openpgp.load_signatures(read_bytes(sibling, 1 << 20))[0]
            except (openpgp.OpenPGPError, IndexError, TooLarge, ValueError):
                continue
            result, anchor = verify_gpg(ctx, "file.checksums", signature, [data])
            if result.valid:
                return signature_verification(result, anchor), text
            self._signature_finding(view, result, ctx, signature.issuer)
            return None, text
        return None, text

    def _signature_finding(
        self, view: ArtifactView, result: openpgp.Result, ctx: Context, issuer: str | None
    ) -> None:
        subject = Subject.of_artifact(view.ref)
        if result.key is not None:
            ctx.recorder.fail(
                "upstream.signature.invalid", subject, tool=TOOL, detail={"reason": result.reason}
            )
        else:
            ctx.recorder.fail(
                "upstream.signature.untrusted",
                subject,
                tool=TOOL,
                detail={"reason": result.reason, "issuer": issuer},
            )

    def _checksums(self, view: ArtifactView, ctx: Context) -> Inspection:
        try:
            data = read_bytes(view, _LIMIT)
        except TooLarge:
            return Inspection(kind="upstream.checksum-list")
        signed, text = self._list_signature(view, data, ctx)
        listed = checked = 0
        mismatched: list[dict[str, object]] = []
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        for algorithm, expected, name in _entries(text):
            listed += 1
            target = view.resolve(name)
            if target is None:
                continue
            actual = _digest(target, algorithm)
            if actual is None:
                continue
            checked += 1
            if actual != expected:
                mismatched.append({"file": name, "algorithm": algorithm})
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
                continue
            verifications[target.ref] = (
                signed
                if signed is not None
                else Verification(
                    "checksum-list", TrustLevel.CHECKSUM, Result.PASS, anchor=name_of(view.ref)
                ),
            )
        if checked and not mismatched:
            ctx.recorder.passed("upstream.checksum-mismatch", checked)
        summary = {"listed": listed, "checked": checked, "signed": signed is not None}
        return Inspection(
            kind="upstream.checksum-list",
            metadata={"checksumList": summary},
            verifications=verifications,
        )

    def _detached(self, view: ArtifactView, ctx: Context) -> Inspection:
        target = view.resolve(name_of(view.ref).rsplit(".", 1)[0])
        if target is None:
            return Inspection(kind="upstream.signature", metadata={"signature": {"target": None}})
        try:
            signature = openpgp.load_signatures(read_bytes(view, 1 << 20))[0]
        except (openpgp.OpenPGPError, IndexError, TooLarge, ValueError) as exc:
            ctx.recorder.fail(
                "upstream.signature.invalid",
                Subject.of_artifact(view.ref),
                tool=TOOL,
                detail={"reason": str(exc)},
            )
            return Inspection(kind="upstream.signature")
        with target.open() as stream:
            chunks = iter(lambda: stream.read(1 << 20), b"")
            result, anchor = verify_gpg(ctx, "file.signed", signature, chunks)
        verifications: dict[ArtifactRef, tuple[Verification, ...]] = {}
        if result.valid:
            verifications[target.ref] = (signature_verification(result, anchor),)
            ctx.recorder.passed("upstream.signature.invalid")
            ctx.recorder.passed("upstream.signature.untrusted")
        else:
            self._signature_finding(view, result, ctx, signature.issuer)
        summary = {
            "target": name_of(target.ref),
            "issuer": signature.issuer,
            "verified": result.valid,
        }
        return Inspection(
            kind="upstream.signature", metadata={"signature": summary}, verifications=verifications
        )
