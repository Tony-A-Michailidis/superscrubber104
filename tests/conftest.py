"""Shared test configuration.

The tool must never make network calls, so the test suite blocks socket creation
outright. A test that needs a socket is a design error, not a test to exempt.
"""

import socket
from collections.abc import Iterator
from typing import Any, NoReturn

import pytest


class NetworkAccessError(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def guard(*args: Any, **kwargs: Any) -> NoReturn:
        raise NetworkAccessError("airlock must not open network connections")

    monkeypatch.setattr(socket, "socket", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)
    yield
