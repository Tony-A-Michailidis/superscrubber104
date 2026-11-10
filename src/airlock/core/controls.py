"""Security control catalogue and rule-to-control mapping."""

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from importlib import resources

from airlock.core.errors import ConfigError, RuleError
from airlock.core.yamlio import Reader, load_yaml

DEFAULT_FRAMEWORK = "nist-800-53r5"


@dataclass(frozen=True, slots=True)
class Control:
    id: str  # "SI-7"
    title: str

    @property
    def family(self) -> str:
        return self.id.split("-", 1)[0]


@dataclass(frozen=True, slots=True)
class ControlCatalog:
    framework: str
    title: str
    controls: Mapping[str, Control]

    def __contains__(self, control_id: object) -> bool:
        return control_id in self.controls

    def __iter__(self) -> Iterator[Control]:
        return iter(self.controls.values())

    def get(self, control_id: str) -> Control:
        return self.controls[control_id]

    def knows(self, control_id: str) -> bool:
        """True for a listed control, or an enhancement such as ``SI-7(1)`` of a listed one."""
        base, paren, rest = control_id.partition("(")
        if paren and not (rest.endswith(")") and rest[:-1].isdigit()):
            return False
        return base in self.controls

    def check(self, control_ids: Sequence[str], context: str) -> None:
        unknown = [c for c in control_ids if not self.knows(c)]
        if unknown:
            raise RuleError(f"{context}: unknown control(s) for {self.framework}: {unknown}")

    @classmethod
    def builtin(cls, framework: str = DEFAULT_FRAMEWORK) -> "ControlCatalog":
        resource = resources.files("airlock.core") / "data" / f"{framework}.yaml"
        if not resource.is_file():
            raise ConfigError(f"no built-in control catalogue named {framework!r}")
        return cls.parse(resource.read_text(encoding="utf-8"), source=f"builtin:{framework}")

    @classmethod
    def parse(cls, text: str, *, source: str) -> "ControlCatalog":
        doc = Reader(load_yaml(text, source), source=source)
        framework = doc.req_str("framework")
        title = doc.req_str("title")
        controls: dict[str, Control] = {}
        for control_id, control_title, _ in doc.mapping("controls"):
            if not isinstance(control_title, str):
                raise doc.error("control titles must be strings", f"controls.{control_id}")
            controls[control_id] = Control(control_id, control_title)
        doc.done()
        return cls(framework, title, controls)


@dataclass(frozen=True, slots=True)
class ControlOverride:
    rule: str  # rule id glob, e.g. "offline.*"
    controls: tuple[str, ...]


class ControlMapping:
    """Controls for a rule: the first matching policy override replaces the rule's own mapping."""

    def __init__(self, catalog: ControlCatalog, overrides: Sequence[ControlOverride] = ()) -> None:
        for override in overrides:
            catalog.check(override.controls, f"controls override {override.rule!r}")
        self.catalog = catalog
        self.overrides = tuple(overrides)

    def controls_for(self, rule_id: str, declared: tuple[str, ...]) -> tuple[str, ...]:
        for override in self.overrides:
            if fnmatchcase(rule_id, override.rule):
                return override.controls
        return declared
