import pytest

from superscrubber104.core.canonical import canonical_bytes, digest, jsonable
from superscrubber104.core.errors import SerializationError


def test_sorted_compact_utf8() -> None:
    assert (
        canonical_bytes({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()
    )


def test_key_order_does_not_change_digest() -> None:
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_digest_format() -> None:
    value = digest({})
    assert value.startswith("sha256:")
    assert len(value) == len("sha256:") + 64


@pytest.mark.parametrize(
    "value",
    [
        {"x": 1.5},
        ["é"],  # decomposed "é": not NFC
        {"x": object()},
    ],
)
def test_rejects_non_canonical(value: object) -> None:
    with pytest.raises(SerializationError):
        canonical_bytes(value)  # type: ignore[arg-type]


def test_jsonable_makes_metadata_canonical() -> None:
    raw = {"temperature": 0.7, "ids": (1, 2), "blob": b"\x01\xff", 3: {"x"}, "name": "é"}
    safe = jsonable(raw)
    assert safe == {"temperature": "0.7", "ids": [1, 2], "blob": "01ff", "3": ["x"], "name": "é"}
    canonical_bytes(safe)
