"""Unit assemblers: they turn handlers' claims into units and check each unit as a whole."""

from airlock.core.interfaces import UnitAssembler
from airlock.core.model import UnitKind
from airlock.units.container_image import ContainerImageAssembler
from airlock.units.dataset import DatasetAssembler
from airlock.units.knowledge_base import KnowledgeBaseAssembler
from airlock.units.locked_env import LockedEnvironmentAssembler
from airlock.units.model_package import ModelPackageAssembler
from airlock.units.node_env import NodeEnvironmentAssembler
from airlock.units.python_env import PythonEnvironmentAssembler
from airlock.units.repo_mirror import RepoMirrorAssembler
from airlock.units.runtime_profile import RuntimeProfileAssembler
from airlock.units.vm_image import VmImageAssembler


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
        LockedEnvironmentAssembler(UnitKind.JVM_ENVIRONMENT, "maven"),
        LockedEnvironmentAssembler(UnitKind.GO_ENVIRONMENT, "go"),
        LockedEnvironmentAssembler(UnitKind.RUST_ENVIRONMENT, "cargo"),
        LockedEnvironmentAssembler(UnitKind.DOTNET_ENVIRONMENT, "nuget"),
        LockedEnvironmentAssembler(UnitKind.TERRAFORM_ENVIRONMENT, "terraform"),
    )
