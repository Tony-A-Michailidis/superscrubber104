"""Artifact handlers."""

from airlock.core.interfaces import Handler
from airlock.handlers.ai import ai_handlers
from airlock.handlers.generic import GenericHandler


def default_handlers() -> tuple[Handler, ...]:
    """Handlers in dispatch order. The generic handler goes last and accepts everything."""
    return (*ai_handlers(), GenericHandler())
