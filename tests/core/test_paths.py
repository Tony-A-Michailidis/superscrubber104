import pytest

from airlock.core.paths import path_matches, validate_bundle_path


@pytest.mark.parametrize("path", ["a", "models/x.safetensors", "a b/ü.txt", ".hidden/file"])
def test_valid_paths(path: str) -> None:
    assert validate_bundle_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/etc/passwd",
        "C:/x",
        "c:x",
        "a\\b",
        "../x",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        "a\x00b",
        "e\u0301",
    ],
)
def test_invalid_paths(path: str) -> None:
    with pytest.raises(ValueError):
        validate_bundle_path(path)


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("models/**", "models/a/b.bin", True),
        ("models/**", "models", False),
        ("**/*.pt", "x.pt", True),
        ("**/*.pt", "a/b/x.pt", True),
        ("*.pt", "a/x.pt", False),
        ("app/*.py", "app/main.py", True),
        ("app/*.py", "app/sub/main.py", False),
        ("a?c", "abc", True),
        ("a?c", "a/c", False),
        ("images/app.tar!/**", "images/app.tar!/layer/x", True),
        ("a.b", "axb", False),
    ],
)
def test_glob(pattern: str, path: str, expected: bool) -> None:
    assert path_matches(pattern, path) is expected
