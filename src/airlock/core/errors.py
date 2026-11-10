"""Exception hierarchy."""


class AirlockError(Exception):
    """Base class for all airlock errors."""


class ConfigError(AirlockError):
    """A policy, transfer request or other input document is invalid.

    ``location`` is the document path to the offending value, e.g. ``rules[3].disposition``.
    """

    def __init__(self, message: str, *, source: str | None = None, location: str = "") -> None:
        self.source = source
        self.location = location
        where = ": ".join(part for part in (source, location) if part)
        super().__init__(f"{where}: {message}" if where else message)


class SerializationError(AirlockError):
    """A document could not be encoded to, or decoded from, its JSON form."""


class RuleError(AirlockError):
    """A rule is unknown, registered twice, or declares unknown controls."""
