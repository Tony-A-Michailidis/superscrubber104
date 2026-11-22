"""Bundle path rules, hostile-name handling and glob matching.

Bundle paths are relative, POSIX-separated and NFC-normalised, with no ``.``/``..`` or empty
segments. Anything else is never "cleaned" into a different location: it is recorded in an
escaped form, flagged, and never used as a filesystem path.
"""

import functools
import posixpath
import re
import unicodedata
from enum import StrEnum

_DRIVE = re.compile(r"^[A-Za-z]:")
_SEPARATORS = re.compile(r"[/\\]")
_KEEP = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/ +=,@~()[]{}#&';:^$"
)


def validate_bundle_path(path: str) -> str:
    """Return ``path`` unchanged if it is a valid bundle path, else raise ValueError."""
    if not path:
        raise ValueError("empty path")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        raise ValueError(f"control character in path {path!r}")
    if "\\" in path:
        raise ValueError(f"backslash in path {path!r}; use '/'")
    if path.startswith("/") or _DRIVE.match(path):
        raise ValueError(f"absolute path {path!r}")
    try:
        normalised = unicodedata.normalize("NFC", path)
        path.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"path is not valid Unicode: {path!r}") from None
    if normalised != path:
        raise ValueError(f"path is not NFC-normalised: {path!r}")
    for segment in path.split("/"):
        if segment in ("", ".", ".."):
            raise ValueError(f"invalid segment {segment!r} in path {path!r}")
    return path


def is_bundle_path(path: str) -> bool:
    try:
        validate_bundle_path(path)
    except ValueError:
        return False
    return True


def escape_name(raw: str) -> str:
    """Printable, unambiguous record of a hostile or unrepresentable name.

    Bytes outside a conservative ASCII set are percent-encoded (a backslash becomes ``%5C``) and
    undecodable bytes survive. ``../x`` stays readable; the reference carrying it is marked unsafe.
    """
    data = raw.encode("utf-8", "surrogateescape")
    return "".join(chr(b) if b in _KEEP else f"%{b:02X}" for b in data) or "%"


def copy_name(name: str, copy: int) -> str:
    """Name for the ``copy``-th copy (2, 3, ...) of a member name an archive holds more than once.

    ``models/a/config.json`` gives ``models/a/%00copy-2/config.json``: the file name is kept so
    that handlers still recognise the file, and ``%00`` cannot come from a decoded name (a NUL
    is never a valid name character). Only ever used on an unsafe reference.
    """
    head, _, base = name.rpartition("/")
    marker = f"%00copy-{copy}"
    return f"{head}/{marker}/{base}" if head else f"{marker}/{base}"


class NameIssue(StrEnum):
    TRAVERSAL = "traversal"  # would land outside the extraction directory
    UNSAFE = "unsafe"  # not representable as a bundle path


def check_member_name(name: str) -> tuple[str, NameIssue | None]:
    """Classify an archive member name.

    Returns ``(recorded name, issue)``. A harmless leading ``./`` and trailing ``/`` are dropped;
    the recorded name is empty for the archive root itself. Names with an issue are escaped.
    """
    segments = _SEPARATORS.split(name)
    if name.startswith(("/", "\\")) or _DRIVE.match(name) or ".." in segments:
        return escape_name(name), NameIssue.TRAVERSAL
    cleaned = name
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.rstrip("/")
    if cleaned in ("", "."):
        return "", None
    if is_bundle_path(cleaned):
        return cleaned, None
    return escape_name(name), NameIssue.UNSAFE


def link_escapes(member: str, target: str, *, hard: bool) -> bool:
    """Whether a link inside an archive points outside the archive root.

    Symlink targets resolve relative to the member's directory; hardlink targets are relative
    to the archive root.
    """
    target = target.replace("\\", "/")
    if target.startswith("/") or _DRIVE.match(target):
        return True
    base = "" if hard else posixpath.dirname(member)
    resolved = posixpath.normpath(posixpath.join(base, target))
    return resolved == ".." or resolved.startswith("../")


@functools.lru_cache(maxsize=1024)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out), re.DOTALL)


def path_matches(pattern: str, path: str) -> bool:
    """Match a bundle path against a glob: ``*`` and ``?`` stay within a segment, ``**`` spans."""
    return _glob_regex(pattern).fullmatch(path) is not None


def has_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")
