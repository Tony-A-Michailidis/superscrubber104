"""Bundle path rules and glob matching.

Bundle paths are relative, POSIX-separated and NFC-normalised, with no ``.``/``..`` or empty
segments. Anything else is rejected rather than "cleaned", so a hostile name can never be
reinterpreted into a different location.
"""

import functools
import re
import unicodedata

_DRIVE = re.compile(r"^[A-Za-z]:")


def validate_bundle_path(path: str) -> str:
    """Return ``path`` unchanged if it is a valid bundle path, else raise ValueError."""
    if not path:
        raise ValueError("empty path")
    if "\x00" in path:
        raise ValueError(f"NUL byte in path {path!r}")
    if "\\" in path:
        raise ValueError(f"backslash in path {path!r}; use '/'")
    if path.startswith("/") or _DRIVE.match(path):
        raise ValueError(f"absolute path {path!r}")
    if unicodedata.normalize("NFC", path) != path:
        raise ValueError(f"path is not NFC-normalised: {path!r}")
    for segment in path.split("/"):
        if segment in ("", ".", ".."):
            raise ValueError(f"invalid segment {segment!r} in path {path!r}")
    return path


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
