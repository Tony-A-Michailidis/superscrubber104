from pathlib import Path

import pytest

from airlock.core.canonical import sha256_digest
from airlock.core.errors import ConfigError
from airlock.core.model import UnitKind
from airlock.core.request import Direction, load_request, parse_request

EXAMPLE = Path(__file__).parents[2] / "examples" / "request.yaml"


def test_example_request() -> None:
    request = load_request(EXAMPLE)
    assert request.id == "TR-2026-0001"
    assert request.direction is Direction.LOW_TO_HIGH
    assert request.allow_undeclared is False
    assert request.contents[0].unit is UnitKind.MODEL_PACKAGE
    assert request.digest == sha256_digest(EXAMPLE.read_bytes())


@pytest.mark.parametrize(
    ("path", "entry"),
    [
        ("models/tiny-chat/model.safetensors", "chat-model"),
        ("app/main.py", "app"),
        ("app/requirements.lock", "app"),  # first match wins
        ("wheels/numpy-2.1.0.whl", "wheelhouse"),
        ("notes.txt", None),
    ],
)
def test_entry_for(path: str, entry: str | None) -> None:
    found = load_request(EXAMPLE).entry_for(path)
    assert (found.name if found else None) == entry


def _modified(old: str, new: str) -> bytes:
    text = EXAMPLE.read_text(encoding="utf-8")
    assert old in text
    return text.replace(old, new).encode()


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("direction: low-to-high", "direction: high-to-low", r"spec\.direction"),
        ("unit: model-package", "unit: model", r"spec\.contents\[0\]\.unit"),
        ("name: app\n", "name: chat-model\n", "content names must be unique"),
        ('paths: ["app/**"]', "paths: []", "at least one path glob"),
        ("role: security", "role: security\n      keyId: bob", "keyId"),
        ("allowUndeclared: false", "allowUndeclared: no-thanks", "true or false"),
        ("  source: dev-unclass", "  sauce: dev-unclass", "required"),
    ],
)
def test_invalid_requests(old: str, new: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_request(_modified(old, new), "request.yaml")
