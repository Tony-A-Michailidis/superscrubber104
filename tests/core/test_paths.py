import pytest

from superscrubber104.core.paths import (
    NameIssue,
    check_member_name,
    escape_name,
    link_escapes,
    path_matches,
    validate_bundle_path,
)


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
        "a\nb",
        "e\u0301",
        "bad\udcff",
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


@pytest.mark.parametrize(
    ("name", "recorded", "issue"),
    [
        ("app/main.py", "app/main.py", None),
        ("./app/", "app", None),
        ("./", "", None),
        ("../../etc/passwd", "../../etc/passwd", NameIssue.TRAVERSAL),
        ("/etc/passwd", "/etc/passwd", NameIssue.TRAVERSAL),
        ("a/../../b", "a/../../b", NameIssue.TRAVERSAL),
        ("..\\..\\evil.dll", "..%5C..%5Cevil.dll", NameIssue.TRAVERSAL),
        ("C:\\Windows\\x", "C:%5CWindows%5Cx", NameIssue.TRAVERSAL),
        ("a\\b", "a%5Cb", NameIssue.UNSAFE),
        ("a//b", "a//b", NameIssue.UNSAFE),
        ("bad\udcff", "bad%FF", NameIssue.UNSAFE),
        ("e\u0301.txt", "e%CC%81.txt", NameIssue.UNSAFE),
        ("new\nline", "new%0Aline", NameIssue.UNSAFE),
    ],
)
def test_member_names(name: str, recorded: str, issue: NameIssue | None) -> None:
    assert check_member_name(name) == (recorded, issue)


def test_escape_is_printable_ascii() -> None:
    escaped = escape_name("a\x00b\\c!d%e\udc80é")
    assert escaped == "a%00b%5Cc%21d%25e%80%C3%A9"


@pytest.mark.parametrize(
    ("member", "target", "hard", "escapes"),
    [
        ("lib/a.so", "b.so", False, False),
        ("lib/a.so", "../bin/x", False, False),
        ("lib/a.so", "../../etc/passwd", False, True),
        ("a", "/etc/passwd", False, True),
        ("a", "..\\..\\x", False, True),
        ("lib/a", "lib/b", True, False),
        ("lib/a", "../b", True, True),
    ],
)
def test_link_escapes(member: str, target: str, hard: bool, escapes: bool) -> None:
    assert link_escapes(member, target, hard=hard) is escapes
