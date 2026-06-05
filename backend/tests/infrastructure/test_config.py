"""Tests der AppConfig-Felder fuer den traffic-Poller (T.4b-2).

Prueft die Defaults (AUTO aus, Intervall 1.0s) und das Env-Override ueber den
``CERNIS_``-Praefix (pydantic-settings). Die uebrigen Felder sind anderweitig durch
die App-Smoke-/Bootstrap-Tests abgedeckt; hier nur die NEUEN traffic-Felder.
"""

import pytest

from infrastructure.config import AppConfig


def test_traffic_poll_defaults() -> None:
    cfg = AppConfig()
    # Default: AUTO aus (sparsam, on-demand), Intervall 1.0s (Vision-Regler).
    assert cfg.traffic_poll_auto is False
    assert cfg.traffic_poll_interval == 1.0


def test_traffic_poll_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CERNIS_TRAFFIC_POLL_AUTO", "true")
    monkeypatch.setenv("CERNIS_TRAFFIC_POLL_INTERVAL", "0.25")
    cfg = AppConfig()
    assert cfg.traffic_poll_auto is True
    assert cfg.traffic_poll_interval == 0.25
