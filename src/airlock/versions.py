"""Version comparisons for runtime compatibility rules.

A constraint is a comma-separated list of clauses, all of which must hold. A clause is an
operator and a version (``>=550.54.14``, ``<13``, ``==12.4``, ``!=2.4.0``) or a glob (``12.*``,
``2.4.*``). Versions compare by their leading numeric parts, so ``12.4`` < ``12.4.1`` and the
local part of ``2.4.0+cu121`` is ignored; a glob matches the whole version string.
"""

import re
from fnmatch import fnmatchcase

_OPERATOR = re.compile(r"^(>=|<=|==|!=|>|<)\s*(.+)$")


def numeric(version: str) -> tuple[int, ...]:
    """The leading dotted numbers of a version: ``"2.4.0+cu121"`` -> ``(2, 4, 0)``."""
    parts = []
    for piece in re.split(r"[.\-_]", version.split("+", 1)[0].lstrip("vV")):
        match = re.match(r"\d+", piece)
        if not match:
            break
        parts.append(int(match.group(0)))
        if match.end() < len(piece):
            break
    return tuple(parts)


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a, b = left + (0,) * (width - len(left)), right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def satisfies(version: str, constraint: str) -> bool:
    for clause in (c.strip() for c in constraint.split(",")):
        if not clause:
            continue
        match = _OPERATOR.match(clause)
        if match is None:
            if not fnmatchcase(version, clause) and not fnmatchcase(
                version.split("+", 1)[0], clause
            ):
                return False
            continue
        operator, wanted = match.groups()
        have, want = numeric(version), numeric(wanted)
        if not have or not want:
            return False
        order = _compare(have, want)
        ok = {
            ">=": order >= 0,
            "<=": order <= 0,
            ">": order > 0,
            "<": order < 0,
            "==": order == 0,
            "!=": order != 0,
        }[operator]
        if not ok:
            return False
    return True


def matches_declared(found: str, declared: str) -> bool:
    """A declared ``12.4`` accepts ``12.4.1``; operators and globs are honoured."""
    if _OPERATOR.match(declared) or any(c in declared for c in "*?["):
        return satisfies(found, declared)
    want = numeric(declared)
    if want and numeric(found)[: len(want)] == want:
        return True
    return found.split("+", 1)[0] == declared.split("+", 1)[0]
