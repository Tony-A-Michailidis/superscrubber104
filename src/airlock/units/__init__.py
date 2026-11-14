"""Unit assemblers: they turn handlers' claims into units and check each unit as a whole."""

from airlock.core.interfaces import UnitAssembler
from airlock.units.container_image import ContainerImageAssembler
from airlock.units.model_package import ModelPackageAssembler
from airlock.units.node_env import NodeEnvironmentAssembler
from airlock.units.python_env import PythonEnvironmentAssembler


def default_assemblers() -> tuple[UnitAssembler, ...]:
    return (
        ModelPackageAssembler(),
        ContainerImageAssembler(),
        PythonEnvironmentAssembler(),
        NodeEnvironmentAssembler(),
    )
