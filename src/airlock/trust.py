"""Vendor keys pinned in the policy, loaded once per run and selected by what they may vouch for.

``trust.upstream`` entries name a key file, pinned by hash, and a ``scope``: globs over what the
key may vouch for (``package.rpm``, ``repo.dnf``, ``repo.apt``, ``file.*``, ``model.*``). A key is
only ever used within its scope and its validity dates, so an Ubuntu archive key cannot vouch for
an RPM, and an expired key vouches for nothing.
"""

import re
from collections.abc import Iterable
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from airlock.core.interfaces import Context
from airlock.core.model import Result, TrustLevel, Verification
from airlock.core.policy import UpstreamKey, UpstreamKeyType
from airlock.formats import openpgp


@lru_cache(maxsize=64)
def _load(path: Path, sha256: str) -> tuple[openpgp.PublicKey, ...]:
    # The policy loader has already checked the file against its pin; the hash keys the cache.
    try:
        return tuple(openpgp.load_keys(path.read_bytes()))
    except (OSError, openpgp.OpenPGPError):
        return ()


def gpg_keys(ctx: Context, scope: str) -> list[tuple[UpstreamKey, tuple[openpgp.PublicKey, ...]]]:
    """Pinned OpenPGP keys allowed to vouch for ``scope``, valid today."""
    today = ctx.now.date()
    found = []
    for key in ctx.policy.upstream:
        if key.type is not UpstreamKeyType.GPG or key.validity.problem(today) is not None:
            continue
        if not any(fnmatchcase(scope, pattern) for pattern in key.scope):
            continue
        keys = _load(key.file.path, key.file.sha256)
        if key.fingerprints:
            allowed = {f.replace(" ", "").upper() for f in key.fingerprints}
            keys = tuple(k for k in keys if k.fingerprint in allowed)
        if keys:
            found.append((key, keys))
    return found


def verify_gpg(
    ctx: Context, scope: str, signature: openpgp.Signature, chunks: Iterable[bytes]
) -> tuple[openpgp.Result, str | None]:
    """Verify with the keys pinned for ``scope``, reading ``chunks`` once. Returns the result and
    the name of the anchor whose key verified it."""
    pinned = gpg_keys(ctx, scope)
    if not pinned:
        return openpgp.Result(False, reason=f"no OpenPGP key is pinned for {scope}"), None
    owner = {key.fingerprint: anchor.name for anchor, keys in pinned for key in keys}
    keys = [key for _, group in pinned for key in group]
    result = openpgp.verify(signature, chunks, keys, at=ctx.now)
    return result, owner.get(result.key.fingerprint) if result.valid and result.key else None


def x509_keys(ctx: Context, scope: str) -> list[tuple[str, object]]:
    """(anchor name, public key) for every certificate or public key pinned for ``scope``."""
    today = ctx.now.date()
    found: list[tuple[str, object]] = []
    for key in ctx.policy.upstream:
        if key.type is not UpstreamKeyType.X509 or key.validity.problem(today) is not None:
            continue
        if not any(fnmatchcase(scope, pattern) for pattern in key.scope):
            continue
        data = key.file.path.read_bytes()
        for block in re.findall(rb"-----BEGIN [A-Z ]+-----.+?-----END [A-Z ]+-----", data, re.S):
            try:
                if b"CERTIFICATE" in block[:40]:
                    found.append((key.name, x509.load_pem_x509_certificate(block).public_key()))
                else:
                    found.append((key.name, load_pem_public_key(block)))
            except ValueError:
                continue
    return found


def signature_verification(result: openpgp.Result, anchor: str | None) -> Verification:
    return Verification(
        "gpg",
        TrustLevel.SIGNATURE,
        Result.PASS,
        signer=result.key.fingerprint if result.key else None,
        anchor=anchor,
    )
