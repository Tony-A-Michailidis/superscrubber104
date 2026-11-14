"""Artifact handlers."""

from airlock.core.interfaces import Handler
from airlock.handlers.agents import AgentHandler
from airlock.handlers.ai import ai_handlers
from airlock.handlers.containers import ContainerImageHandler
from airlock.handlers.datasets import DatasetHandler
from airlock.handlers.documents import DocumentHandler
from airlock.handlers.executables import ExecutableHandler
from airlock.handlers.generic import GenericHandler
from airlock.handlers.knowledge import KnowledgeBaseHandler
from airlock.handlers.notebooks import NotebookHandler
from airlock.handlers.packages.node import NodePackageHandler
from airlock.handlers.packages.os import OSPackageHandler
from airlock.handlers.packages.python import PythonPackageHandler
from airlock.handlers.secrets import SecretsHandler
from airlock.handlers.source import SourceHandler


def default_handlers() -> tuple[Handler, ...]:
    """Handlers in dispatch order. Every handler whose ``detect`` matches runs; the generic
    handler goes last and accepts everything."""
    return (
        *ai_handlers(),
        AgentHandler(),
        ContainerImageHandler(),
        OSPackageHandler(),
        PythonPackageHandler(),
        NodePackageHandler(),
        KnowledgeBaseHandler(),
        DatasetHandler(),
        NotebookHandler(),
        DocumentHandler(),
        ExecutableHandler(),
        SourceHandler(),
        SecretsHandler(),
        GenericHandler(),
    )
