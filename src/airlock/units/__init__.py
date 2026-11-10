"""Unit assemblers: they turn handlers' claims into units and check each unit as a whole."""

from airlock.core.interfaces import UnitAssembler
from airlock.units.model_package import ModelPackageAssembler


def default_assemblers() -> tuple[UnitAssembler, ...]:
    return (ModelPackageAssembler(),)
