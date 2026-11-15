"""Artifact handlers."""

from airlock.core.interfaces import Handler
from airlock.handlers.agents import AgentHandler
from airlock.handlers.ai import ai_handlers
from airlock.handlers.containers import ContainerImageHandler
from airlock.handlers.corpus import CorpusHandler
from airlock.handlers.datasets import DatasetHandler
from airlock.handlers.documents import DocumentHandler
from airlock.handlers.evals import EvalHandler
from airlock.handlers.executables import ExecutableHandler
from airlock.handlers.generic import GenericHandler
from airlock.handlers.knowledge import KnowledgeBaseHandler
from airlock.handlers.mirrors import MirrorHandler
from airlock.handlers.notebooks import NotebookHandler
from airlock.handlers.offline import OfflineHandler
from airlock.handlers.packages.cargo import CargoHandler
from airlock.handlers.packages.golang import GoHandler
from airlock.handlers.packages.jvm import JvmHandler
from airlock.handlers.packages.linux import LinuxPackageHandler
from airlock.handlers.packages.node import NodePackageHandler
from airlock.handlers.packages.nuget import NuGetHandler
from airlock.handlers.packages.os import OSPackageHandler
from airlock.handlers.packages.python import PythonPackageHandler
from airlock.handlers.runtime import RuntimeHandler
from airlock.handlers.secrets import SecretsHandler
from airlock.handlers.source import SourceHandler
from airlock.handlers.upstream import UpstreamHandler


def default_handlers() -> tuple[Handler, ...]:
    """Handlers in dispatch order. Every handler whose ``detect`` matches runs; the generic
    handler goes last and accepts everything."""
    return (
        *ai_handlers(),
        AgentHandler(),
        ContainerImageHandler(),
        LinuxPackageHandler(),
        JvmHandler(),
        GoHandler(),
        CargoHandler(),
        NuGetHandler(),
        MirrorHandler(),
        OSPackageHandler(),
        PythonPackageHandler(),
        NodePackageHandler(),
        KnowledgeBaseHandler(),
        CorpusHandler(),
        DatasetHandler(),
        NotebookHandler(),
        EvalHandler(),
        DocumentHandler(),
        RuntimeHandler(),
        ExecutableHandler(),
        UpstreamHandler(),
        SourceHandler(),
        OfflineHandler(),
        SecretsHandler(),
        GenericHandler(),
    )
