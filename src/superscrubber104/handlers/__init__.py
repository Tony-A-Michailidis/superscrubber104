"""Artifact handlers."""

from superscrubber104.core.interfaces import Handler
from superscrubber104.handlers.agents import AgentHandler
from superscrubber104.handlers.ai import ai_handlers
from superscrubber104.handlers.containers import ContainerImageHandler
from superscrubber104.handlers.corpus import CorpusHandler
from superscrubber104.handlers.datasets import DatasetHandler
from superscrubber104.handlers.documents import DocumentHandler
from superscrubber104.handlers.evals import EvalHandler
from superscrubber104.handlers.executables import ExecutableHandler
from superscrubber104.handlers.generic import GenericHandler
from superscrubber104.handlers.hauler import HaulHandler
from superscrubber104.handlers.iac import IacHandler
from superscrubber104.handlers.ide import IdeExtensionHandler
from superscrubber104.handlers.knowledge import KnowledgeBaseHandler
from superscrubber104.handlers.mirrors import MirrorHandler
from superscrubber104.handlers.notebooks import NotebookHandler
from superscrubber104.handlers.offline import OfflineHandler
from superscrubber104.handlers.packages.cargo import CargoHandler
from superscrubber104.handlers.packages.golang import GoHandler
from superscrubber104.handlers.packages.jvm import JvmHandler
from superscrubber104.handlers.packages.linux import LinuxPackageHandler
from superscrubber104.handlers.packages.node import NodePackageHandler
from superscrubber104.handlers.packages.nuget import NuGetHandler
from superscrubber104.handlers.packages.os import OSPackageHandler
from superscrubber104.handlers.packages.python import PythonPackageHandler
from superscrubber104.handlers.runtime import RuntimeHandler
from superscrubber104.handlers.secrets import SecretsHandler
from superscrubber104.handlers.source import SourceHandler
from superscrubber104.handlers.upstream import UpstreamHandler
from superscrubber104.handlers.vm import VmHandler
from superscrubber104.handlers.zarf import ZarfPackageHandler


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
        IacHandler(),
        IdeExtensionHandler(),
        VmHandler(),
        ZarfPackageHandler(),
        HaulHandler(),
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
