"""Canonical JSON: the only byte form that is ever hashed or signed.

UTF-8, keys sorted by code point, no insignificant whitespace, no floats. This is the subset of
RFC 8785 (JCS) that our documents need; for documents without floats the output is identical.
"""

import hashlib
import json
import unicodedata
from collections.abc import Mapping, Sequence
from typing import TypeAlias, Union

from airlock.core.errors import SerializationError

# Union[] rather than "|": a recursive alias needs string forward references.
JSON: TypeAlias = Union[str, int, bool, list["JSON"], dict[str, "JSON"], None]  # noqa: UP007


def _check(value: object, where: str) -> None:
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise SerializationError(f"{where}: string is not NFC-normalised")
        return
    if isinstance(value, float):
        raise SerializationError(f"{where}: floats are not allowed in canonical documents")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SerializationError(f"{where}: object keys must be strings, got {key!r}")
            _check(key, where)
            _check(item, f"{where}.{key}")
        return
    if isinstance(value, Sequence):
        for index, item in enumerate(value):
            _check(item, f"{where}[{index}]")
        return
    raise SerializationError(f"{where}: {type(value).__name__} is not a JSON value")


def canonical_bytes(data: JSON) -> bytes:
    """Encode ``data`` canonically. Raises SerializationError for non-canonical input."""
    _check(data, "$")
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_digest(raw: bytes) -> str:
    """Digest string in OCI form: ``sha256:<hex>``."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(data: JSON) -> str:
    """Digest of the canonical encoding of ``data``."""
    return sha256_digest(canonical_bytes(data))
