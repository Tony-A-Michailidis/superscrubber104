"""OpenSSF model signatures (``model.sig``): the publisher's own signature over every model file.

The bundle is verified offline against what the policy pins under ``trust.upstream`` with a
scope matching ``model.signature`` (a public key or CA certificate as ``type: x509``; a Sigstore
trusted root with accepted identities as ``type: sigstore``). Then every file the signature
lists is compared, by the sha256 the walk already computed, with the digest it was signed with.

A signature that does not hold, or a file that differs from what was signed, is an authenticity
failure and final. A signature that holds but not for anyone the policy trusts is a policy
matter. The verified files are reported to the model-package assembler, which records a
``signature``-level verification on each and checks that nothing in the package went unsigned.
"""

from fnmatch import fnmatchcase

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject
from superscrubber104.core.policy import UpstreamKey, UpstreamKeyType
from superscrubber104.formats.sigstore import (
    Bundle,
    BundleError,
    Outcome,
    parse_bundle,
    verify_certificate,
    verify_key,
    verify_sigstore,
)
from superscrubber104.handlers.ai.common import TOOL, claim, name_of
from superscrubber104.handlers.common import read_bytes

_LIMIT = 16 << 20
SCOPE = "model.signature"


def _anchors(ctx: Context, kind: UpstreamKeyType, scope: str) -> list[UpstreamKey]:
    today = ctx.now.date()
    return [
        key
        for key in ctx.policy.upstream
        if key.type is kind
        and any(fnmatchcase(scope, pattern) for pattern in key.scope)
        and key.validity.problem(today) is None
    ]


def verify_bundle(
    bundle: Bundle, ctx: Context, scope: str = SCOPE, what: str = "models"
) -> Outcome:
    """Verify a Sigstore bundle against what the policy pins for ``scope``."""
    if bundle.method == "sigstore":
        roots = [
            (k.name, k.file.path.read_bytes(), k.identities, k.issuers)
            for k in _anchors(ctx, UpstreamKeyType.SIGSTORE, scope)
        ]
        return verify_sigstore(bundle, roots)
    pinned = [
        (k.name, k.file.path.read_bytes()) for k in _anchors(ctx, UpstreamKeyType.X509, scope)
    ]
    if bundle.method == "certificate":
        return verify_certificate(bundle, pinned, ctx.now)
    return verify_key(bundle, pinned, what)


class ModelSignatureHandler:
    name = "model-signature"
    version = "1"
    kinds = frozenset({"model.signature"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        name = name_of(artifact.ref).lower()
        head = artifact.head(65536)  # dsseEnvelope often follows a long certificate
        if name.endswith((".sig", ".sigstore.json", ".sigstore")) and b'"dsseEnvelope"' in head:
            return Detection("model.signature", 80)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        recorder, subject = ctx.recorder, Subject.of_artifact(artifact.ref)
        try:
            bundle = parse_bundle(read_bytes(artifact, _LIMIT))
        except BundleError as exc:
            recorder.fail(
                "model.signature.invalid",
                subject,
                tool=TOOL,
                detail={"reasons": [f"unreadable bundle: {exc}"]},
            )
            return Inspection(kind="model.signature")
        predicate = str(bundle.statement.get("predicateType", ""))
        if not predicate.startswith("https://model_signing/"):
            return Inspection(kind="unclassified")  # some other Sigstore bundle
        outcome = verify_bundle(bundle, ctx)
        detail = {
            "method": outcome.method,
            "status": outcome.status,
            "signer": outcome.signer,
            "anchor": outcome.anchor,
            "reasons": outcome.reasons,
        }
        if outcome.status == "invalid":
            recorder.fail("model.signature.invalid", subject, tool=TOOL, detail=detail)
        else:
            recorder.passed("model.signature.invalid")
        if outcome.status in ("untrusted", "unverifiable"):
            recorder.fail(
                "model.signature.untrusted",
                subject,
                tool=TOOL,
                detail=detail,
                attributes={"status": outcome.status, "method": outcome.method},
            )
        elif outcome.status == "verified":
            recorder.passed("model.signature.untrusted")

        covered: list[str] = []
        missing: list[str] = []
        mismatched: list[str] = []
        resources = bundle.resources()
        reachable = artifact.resolve(name_of(artifact.ref)) is not None
        for name, (algorithm, digest) in sorted(resources.items()):
            target = artifact.resolve(name)
            if target is None:
                missing.append(name)
            elif algorithm != "sha256" or target.sha256 is None:
                continue
            elif target.sha256 != digest:
                mismatched.append(name)
                recorder.fail(
                    "model.signature.digest-mismatch",
                    Subject.of_artifact(target.ref),
                    tool=TOOL,
                    detail={"file": name, "signed": digest, "actual": target.sha256},
                )
            else:
                covered.append(name)
        if not reachable:
            recorder.not_assessed(
                ("model.signature.digest-mismatch",),
                subject,
                tool=TOOL,
                reason="the signature is inside an archive; its files cannot be compared",
            )
        elif not mismatched:
            recorder.passed("model.signature.digest-mismatch", max(len(covered), 1))
        facts = {
            "status": outcome.status,
            "method": outcome.method,
            "signer": outcome.signer,
            "anchor": outcome.anchor,
            "covered": covered,
            "missing": missing if reachable else [],
            "ignored": bundle.ignored(),
            "signature": name_of(artifact.ref),
        }
        return Inspection(
            kind="model.signature",
            metadata={"modelSignature": {k: v for k, v in facts.items() if k != "covered"}},
            claims=(claim(artifact, "signature", facts),),
        )
