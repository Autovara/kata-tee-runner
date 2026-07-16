from __future__ import annotations

import pytest

from room.profile import (
    AGENT_EXECUTION_TIMEOUT_ENV,
    DEFAULT_AGENT_EXECUTION_TIMEOUT_SECONDS,
    resolve_agent_execution_timeout_seconds,
)


def test_agent_execution_timeout_uses_the_production_default(monkeypatch) -> None:
    monkeypatch.delenv(AGENT_EXECUTION_TIMEOUT_ENV, raising=False)
    assert resolve_agent_execution_timeout_seconds() == DEFAULT_AGENT_EXECUTION_TIMEOUT_SECONDS


@pytest.mark.parametrize("value", ["0", "-1", "not-a-number"])
def test_agent_execution_timeout_rejects_invalid_configuration(monkeypatch, value) -> None:
    monkeypatch.setenv(AGENT_EXECUTION_TIMEOUT_ENV, value)
    with pytest.raises(RuntimeError, match=AGENT_EXECUTION_TIMEOUT_ENV):
        resolve_agent_execution_timeout_seconds()


def test_agent_execution_timeout_accepts_a_positive_override(monkeypatch) -> None:
    monkeypatch.setenv(AGENT_EXECUTION_TIMEOUT_ENV, "321.5")
    assert resolve_agent_execution_timeout_seconds() == 321.5
