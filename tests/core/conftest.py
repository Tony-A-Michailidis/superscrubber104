import pytest

from airlock.core.controls import ControlCatalog
from airlock.core.rules import FindingFactory, RuleRegistry
from tests.core.helpers import RULES


@pytest.fixture(scope="session")
def catalog() -> ControlCatalog:
    return ControlCatalog.builtin()


@pytest.fixture
def registry(catalog: ControlCatalog) -> RuleRegistry:
    registry = RuleRegistry(catalog)
    registry.register(*RULES)
    return registry


@pytest.fixture
def findings(registry: RuleRegistry) -> FindingFactory:
    return FindingFactory(registry)
