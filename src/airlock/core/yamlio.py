"""Strict YAML loading for policy, request and catalogue documents.

Two defences on top of ``yaml.safe_load``:

* Duplicate mapping keys are an error. PyYAML otherwise keeps the last one silently, so a second
  ``disposition:`` line could quietly weaken a policy.
* ``Reader`` tracks the document path of every value and rejects unknown keys, so a typo such as
  ``dispositon: block`` is reported instead of ignored.
"""

import functools
import re
from collections.abc import Callable, Iterator
from datetime import date, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

import yaml

from airlock.core.errors import ConfigError

E = TypeVar("E", bound=Enum)
T = TypeVar("T")


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(text: str | bytes, source: str) -> object:
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}", source=source) from exc


class _UntrustedLoader(yaml.SafeLoader):
    """For YAML found in deliveries (model cards). Aliases are refused: a few lines of nested
    aliases expand into billions of nodes for any code that walks the result."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise yaml.composer.ComposerError(
                None, None, "aliases are not allowed", event.start_mark
            )
        return super().compose_node(parent, index)


def load_untrusted_yaml(text: str) -> object:
    """Parse YAML from a delivery. Raises yaml.YAMLError on anything unusual."""
    return yaml.load(text, Loader=_UntrustedLoader)  # noqa: S506 - SafeLoader subclass


def load_yaml_file(path: Path) -> tuple[object, bytes]:
    """Load a YAML file; also return its raw bytes for digesting."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read file: {exc}", source=str(path)) from exc
    return load_yaml(raw, str(path)), raw


_SIZE = re.compile(r"^(\d+)\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)?$")
_SIZE_FACTORS = {
    None: 1, "B": 1,
    "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
    "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "TiB": 2**40,
}  # fmt: skip
_DURATION = re.compile(r"^(\d+)\s*([smhdw])$")
_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


class Reader:
    """Typed, path-tracking view of one YAML mapping. Call ``done()`` to reject unknown keys."""

    def __init__(self, data: object, *, source: str, location: str = "") -> None:
        if not isinstance(data, dict):
            raise ConfigError("expected a mapping", source=source, location=location)
        self._data: dict[Any, Any] = data
        self._source = source
        self._location = location
        self._used: set[str] = set()

    def _loc(self, key: str) -> str:
        return f"{self._location}.{key}" if self._location else key

    def error(self, message: str, key: str | None = None) -> ConfigError:
        location = self._loc(key) if key is not None else self._location
        return ConfigError(message, source=self._source, location=location)

    def names(self) -> list[str]:
        keys = [k for k in self._data if isinstance(k, str)]
        if len(keys) != len(self._data):
            raise self.error("keys must be strings")
        return keys

    def has(self, key: str) -> bool:
        return key in self._data

    def _get(self, key: str, required: bool) -> object:
        self._used.add(key)
        if key not in self._data or self._data[key] is None:
            if required:
                raise self.error("required", key)
            return None
        return self._data[key]

    def _typed(self, key: str, required: bool, kind: type[T], label: str) -> T | None:
        value = self._get(key, required)
        if value is None:
            return None
        if type(value) is not kind:
            raise self.error(f"expected {label}, got {type(value).__name__}", key)
        return value

    def req_str(self, key: str) -> str:
        value = self._typed(key, True, str, "a string")
        assert value is not None  # noqa: S101 - required=True guarantees it
        return value

    def opt_str(self, key: str) -> str | None:
        return self._typed(key, False, str, "a string")

    def opt_int(self, key: str) -> int | None:
        return self._typed(key, False, int, "an integer")

    def opt_bool(self, key: str) -> bool | None:
        return self._typed(key, False, bool, "true or false")

    def opt_date(self, key: str) -> date | None:
        value = self._get(key, False)
        if value is None:
            return None
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            try:
                return date.fromisoformat(value)
            except ValueError:
                pass
        raise self.error("expected a date (YYYY-MM-DD)", key)

    def opt_enum(self, key: str, enum: type[E]) -> E | None:
        value = self._get(key, False)
        if value is None:
            return None
        try:
            return enum(value)
        except ValueError:
            allowed = ", ".join(str(m.value) for m in enum)
            raise self.error(f"{value!r} is not one of: {allowed}", key) from None

    def enum(self, key: str, enum: type[E]) -> E:
        if self._get(key, True) is None:
            raise self.error("required", key)
        value = self.opt_enum(key, enum)
        assert value is not None  # noqa: S101
        return value

    def opt_size(self, key: str) -> int | None:
        """Byte size: an integer, or ``"500GiB"``, ``"25GB"``, ..."""
        value = self._get(key, False)
        if value is None:
            return None
        if type(value) is int and value >= 0:
            return value
        match = _SIZE.match(value) if isinstance(value, str) else None
        if not match:
            raise self.error("expected a size such as 1024, '25GB' or '500GiB'", key)
        return int(match.group(1)) * _SIZE_FACTORS[match.group(2)]

    def opt_duration(self, key: str) -> timedelta | None:
        value = self._get(key, False)
        if value is None:
            return None
        return parse_duration(value, lambda msg: self.error(msg, key))

    def str_list(self, key: str) -> tuple[str, ...]:
        value = self._get(key, False)
        if value is None:
            return ()
        if not isinstance(value, list) or not all(type(v) is str for v in value):
            raise self.error("expected a list of strings", key)
        return tuple(value)

    def opt_section(self, key: str) -> "Reader | None":
        value = self._get(key, False)
        if value is None:
            return None
        return Reader(value, source=self._source, location=self._loc(key))

    def section(self, key: str) -> "Reader":
        return Reader(self._get(key, True), source=self._source, location=self._loc(key))

    def sections(self, key: str) -> Iterator["Reader"]:
        """Each mapping in a list of mappings."""
        value = self._get(key, False)
        if value is None:
            return
        if not isinstance(value, list):
            raise self.error("expected a list", key)
        for index, item in enumerate(value):
            yield Reader(item, source=self._source, location=f"{self._loc(key)}[{index}]")

    def mapping(self, key: str) -> Iterator[tuple[str, object, Callable[[], "Reader"]]]:
        """Entries of a free-form mapping: (key, raw value, factory for a Reader of the value)."""
        value = self._get(key, False)
        if value is None:
            return
        if not isinstance(value, dict):
            raise self.error("expected a mapping", key)
        for name, item in value.items():
            if not isinstance(name, str):
                raise self.error(f"keys must be strings, got {name!r}", key)
            location = f"{self._loc(key)}.{name}"
            factory = functools.partial(Reader, item, source=self._source, location=location)
            yield name, item, factory

    def raw(self, key: str) -> object:
        return self._get(key, False)

    def done(self) -> None:
        unknown = sorted(str(k) for k in self._data if k not in self._used)
        if unknown:
            raise self.error(f"unknown key(s): {', '.join(unknown)}")


def parse_size(value: str) -> int:
    """``"25GB"``, ``"700MiB"`` or a plain byte count, for command-line options."""
    match = _SIZE.match(value.strip())
    if not match:
        raise ValueError("expected a size such as 1048576, '25GB' or '700MiB'")
    return int(match.group(1)) * _SIZE_FACTORS[match.group(2)]


def parse_duration(value: object, error: Callable[[str], ConfigError]) -> timedelta:
    match = _DURATION.match(value) if isinstance(value, str) else None
    if not match:
        raise error("expected a duration such as '30m', '12h', '7d' or '2w'")
    return timedelta(**{_DURATION_UNITS[match.group(2)]: int(match.group(1))})
