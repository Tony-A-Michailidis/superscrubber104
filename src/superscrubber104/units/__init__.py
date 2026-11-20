"""Unit assemblers: they turn handlers' claims into units and check each unit as a whole."""

from superscrubber104.core.interfaces import UnitAssembler
from superscrubber104.core.model import UnitKind
from superscrubber104.units.container_image import ContainerImageAssembler
from superscrubber104.units.dataset import DatasetAssembler
from superscrubber104.units.hauler_haul import HaulAssembler
from superscrubber104.units.knowledge_base import KnowledgeBaseAssembler
from superscrubber104.units.locked_env import LockedEnvironmentAssembler
from superscrubber104.units.model_package import ModelPackageAssembler
from superscrubber104.units.node_env import NodeEnvironmentAssembler
from superscrubber104.units.python_env import PythonEnvironmentAssembler
from superscrubber104.units.repo_mirror import RepoMirrorAssembler
from superscrubber104.units.runtime_profile import RuntimeProfileAssembler
from superscrubber104.units.vm_image import VmImageAssembler
from superscrubber104.units.zarf_package import ZarfPackageAssembler


def default_assemblers() -> tuple[UnitAssembler, ...]:
    return (
        ModelPackageAssembler(),
        ContainerImageAssembler(),
        PythonEnvironmentAssembler(),
        NodeEnvironmentAssembler(),
        DatasetAssembler(),
        KnowledgeBaseAssembler(),
        RuntimeProfileAssembler(),
        RepoMirrorAssembler(),
        VmImageAssembler(),
        ZarfPackageAssembler(),
        HaulAssembler(),
        LockedEnvironmentAssembler(UnitKind.JVM_ENVIRONMENT, "maven"),
        LockedEnvironmentAssembler(UnitKind.GO_ENVIRONMENT, "go"),
        LockedEnvironmentAssembler(UnitKind.RUST_ENVIRONMENT, "cargo"),
        LockedEnvironmentAssembler(UnitKind.DOTNET_ENVIRONMENT, "nuget"),
        LockedEnvironmentAssembler(UnitKind.TERRAFORM_ENVIRONMENT, "terraform"),
    )
