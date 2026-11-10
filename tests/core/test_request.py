from pathlib import Path

import pytest

from airlock.core.canonical import sha256_digest
from airlock.core.errors import ConfigError
from airlock.core.model import UnitKind, UpstreamRef
from airlock.core.request import Direction, Profile, load_request, parse_request

EXAMPLE = Path(__file__).parents[2] / "examples" / "request.yaml"


def test_example_request() -> None:
    request = load_request(EXAMPLE)
    assert request.id == "TR-2026-0001"
    assert request.direction is Direction.LOW_TO_HIGH
    assert request.profile is Profile.ROUTINE
    assert request.stream == "rag-assistant"
    assert request.allow_undeclared is False
    assert request.contents[0].unit is UnitKind.MODEL_PACKAGE
    assert request.contents[0].upstream == UpstreamRef(
        "huggingface", "example-org/tiny-chat", revision="0123456789abcdef0123456789abcdef01234567"
    )
    assert request.digest == sha256_digest(EXAMPLE.read_bytes())


@pytest.mark.parametrize(
    ("path", "entries"),
    [
        ("models/tiny-chat/model.safetensors", ["chat-model"]),
        ("app/main.py", ["app"]),
        ("app/requirements.lock", ["app", "wheelhouse"]),  # a file may belong to several
        ("wheels/numpy-2.1.0.whl", ["wheelhouse"]),
        ("notes.txt", []),
    ],
)
def test_entries_for(path: str, entries: list[str]) -> None:
    assert [e.name for e in load_request(EXAMPLE).entries_for(path)] == entries


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
        ("type: huggingface", "typo: huggingface", r"upstream\.type: required"),
        ("stream: rag-assistant", "profile: urgent", r"spec\.profile"),
    ],
)
def test_invalid_requests(old: str, new: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_request(_modified(old, new), "request.yaml")
