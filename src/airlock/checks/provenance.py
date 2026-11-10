"""The second layer of trust: is each artifact's genuineness established as strongly as policy
requires for its kind?

Policy sets a minimum per kind (``trust.minimum``), for example a verified signature for RPMs and
a pinned checksum for models. Handlers and assemblers record ``Verification`` entries on artifacts
(publisher checksums, signatures, allowlist pins); this check compares the strongest passing one
with the minimum.
"""

from collections.abc import Sequence

from airlock.analyzer import TOOL
from airlock.core.interfaces import Context
from airlock.core.model import Artifact, Result, Subject, TrustLevel


def check_upstream_trust(artifacts: Sequence[Artifact], ctx: Context) -> None:
    policy = ctx.policy
    if not policy.minimum_trust:
        return
    for artifact in artifacts:
        required = max(
            (policy.required_trust(kind) for kind in artifact.kinds),
            key=lambda level: level.rank,
        )
        if required is TrustLevel.NONE:
            continue
        best = max(
            (v.level for v in artifact.verifications if v.result is Result.PASS),
            key=lambda level: level.rank,
            default=TrustLevel.NONE,
        )
        if best.rank >= required.rank:
            ctx.recorder.passed("trust.upstream.insufficient")
            continue
        ctx.recorder.fail(
            "trust.upstream.insufficient",
            Subject.of_artifact(artifact.ref),
            tool=TOOL,
            detail={
                "required": required.value,
                "established": best.value,
                "kinds": [*artifact.kinds],
                "verifications": [
                    {"type": v.type, "level": v.level.value, "result": v.result.value}
                    for v in artifact.verifications
                ],
            },
        )
