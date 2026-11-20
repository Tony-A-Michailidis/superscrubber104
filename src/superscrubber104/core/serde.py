"""Generic conversion between core dataclasses and JSON data.

Field names become camelCase on the wire (``api_version`` -> ``apiVersion``) to match the YAML
documents. ``None`` fields are omitted. Decoding is strict: unknown keys, missing required keys and
wrong types are errors, because a silently ignored field in a signed document is a hole.
"""

import dataclasses
import functools
import types
import typing
from collections.abc import Mapping
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any, TypeVar

from superscrubber104.core.canonical import JSON
from superscrubber104.core.errors import SerializationError

T = TypeVar("T")


def camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.title() for part in rest)


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise SerializationError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def to_data(obj: object) -> JSON:
    """Convert a dataclass (or nested value) to JSON data."""
    if obj is None or isinstance(obj, bool | int | str):
        return obj
    if isinstance(obj, Enum):
        return to_data(obj.value)
    if isinstance(obj, datetime):
        return format_timestamp(obj)
    if isinstance(obj, date):
        return obj.isoformat()
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, JSON] = {}
        for field in dataclasses.fields(obj):
            value = getattr(obj, field.name)
            if value is not None:
                out[camel(field.name)] = to_data(value)
        return out
    if isinstance(obj, Mapping):
        return {_key(k): to_data(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [to_data(item) for item in obj]
    raise SerializationError(f"cannot serialise {type(obj).__name__}")


def _key(key: object) -> str:
    if isinstance(key, Enum):
        key = key.value
    if not isinstance(key, str):
        raise SerializationError(f"mapping keys must be strings, got {key!r}")
    return key


@functools.cache
def _hints(cls: type) -> dict[str, Any]:
    return typing.get_type_hints(cls)


def from_data(cls: type[T], data: object, where: str = "$") -> T:
    """Build an instance of dataclass ``cls`` from JSON data."""
    return typing.cast(T, _decode(cls, data, where))


def _decode(tp: Any, data: object, where: str) -> object:
    if tp is Any or tp == JSON:
        return data
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)

    if origin in (typing.Union, types.UnionType):
        if _is_json_alias(args):
            return data  # free-form JSON; checked when canonically encoded
        if data is None and type(None) in args:
            return None
        options = [a for a in args if a is not type(None)]
        if len(options) != 1:
            raise SerializationError(f"{where}: unsupported union {tp}")
        return _decode(options[0], data, where)

    if origin is tuple:
        if not isinstance(data, list):
            raise SerializationError(f"{where}: expected a list")
        item_type = args[0]
        return tuple(_decode(item_type, item, f"{where}[{i}]") for i, item in enumerate(data))

    if origin in (dict, Mapping, typing.Mapping) or tp is dict:
        if not isinstance(data, dict):
            raise SerializationError(f"{where}: expected an object")
        key_type, value_type = args or (str, Any)
        return {
            _decode(key_type, k, where): _decode(value_type, v, f"{where}.{k}")
            for k, v in data.items()
        }

    if isinstance(tp, type) and issubclass(tp, Enum):
        try:
            return tp(data)
        except ValueError:
            allowed = ", ".join(str(m.value) for m in tp)
            raise SerializationError(f"{where}: {data!r} is not one of: {allowed}") from None

    if tp is datetime:
        if not isinstance(data, str):
            raise SerializationError(f"{where}: expected a timestamp string")
        value = datetime.fromisoformat(data)
        if value.tzinfo is None:
            raise SerializationError(f"{where}: timestamp has no timezone")
        return value

    if tp is date:
        if not isinstance(data, str):
            raise SerializationError(f"{where}: expected a date string")
        return date.fromisoformat(data)

    if dataclasses.is_dataclass(tp) and isinstance(tp, type):
        return _decode_dataclass(tp, data, where)

    if tp in (str, int, bool):
        # bool is a subclass of int; never accept one for the other.
        if type(data) is not tp:
            raise SerializationError(f"{where}: expected {tp.__name__}, got {type(data).__name__}")
        return data

    raise SerializationError(f"{where}: unsupported type {tp}")


def _is_json_alias(args: tuple[Any, ...]) -> bool:
    # get_type_hints() expands the recursive JSON alias, so recognise it by shape.
    return any(typing.get_origin(a) is list for a in args) and any(
        typing.get_origin(a) is dict for a in args
    )


def _decode_dataclass(cls: type, data: object, where: str) -> object:
    if not isinstance(data, dict):
        raise SerializationError(f"{where}: expected an object")
    hints = _hints(cls)
    fields = {camel(f.name): f for f in dataclasses.fields(cls) if f.init}
    unknown = sorted(set(data) - set(fields))
    if unknown:
        raise SerializationError(f"{where}: unknown field(s): {', '.join(unknown)}")
    kwargs: dict[str, object] = {}
    for key, field in fields.items():
        if key in data:
            kwargs[field.name] = _decode(hints[field.name], data[key], f"{where}.{key}")
        elif field.default is dataclasses.MISSING and field.default_factory is dataclasses.MISSING:
            raise SerializationError(f"{where}: missing required field {key!r}")
    try:
        return cls(**kwargs)
    except (TypeError, ValueError) as exc:
        raise SerializationError(f"{where}: {exc}") from exc
