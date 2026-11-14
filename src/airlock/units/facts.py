"""Typed access to claim facts (free-form JSON) for assemblers."""

from airlock.core.canonical import JSON


def as_int(value: object) -> int:
    return value if type(value) is int else 0


def as_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def as_dict(value: object) -> dict[str, JSON]:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[JSON]:
    return value if isinstance(value, list) else []


def dicts(value: object) -> list[dict[str, JSON]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def strings(value: object) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]
