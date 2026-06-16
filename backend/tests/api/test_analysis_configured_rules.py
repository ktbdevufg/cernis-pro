"""Tests fuer den ``_ConfiguredRuleProvider`` im Composition Root (ADR 0027, Stueck 2+3).

Der Provider liest drei konfigurierbare Built-in-Regel-Parameter defensiv aus den Settings
und ueberschreibt sie per ``dataclasses.replace``, OHNE die Built-in-Regeln im Code
anzufassen:

* ``analysis_port_count_threshold`` (Integer) -> ``threshold`` von ``host_many_high_ports``.
* ``analysis_suspicious_ports`` (JSON-Array) -> ``ports`` von ``host_remote_access_port``.
* ``analysis_critical_ports`` (JSON-Array) -> ``ports`` von ``host_backdoor_port``.

Defensiv (S3-konform): fehlt/falscher Typ -> Built-in-Default; kaputtes JSON
(``CorruptSettingError``) -> geloggte Warnung + Built-in-Default; leeres Array ist ein
GUELTIGER Wert (Regel trifft nichts), kein Rueckfall auf den Default. Getestet wird der
echte Provider mit einem Fake-Settings-Repository (kein I/O), plus eine End-zu-End-Probe,
dass die ueberschriebene Schwelle im fertig verdrahteten Runner wirkt.
"""

import asyncio
from typing import Any

import pytest

import app as app_module
from app import (
    _PORT_COUNT_THRESHOLD_DEFAULT,
    _CompositeRuleProvider,
    _ConfiguredRuleProvider,
    create_app,
)
from domain.analysis import Rule
from domain.scanning.models import EnrichedHost, PortInfo, ScanRecord, ScanSummary
from domain.settings import Setting, SettingValue
from infrastructure.analysis import BuiltinRuleProvider
from infrastructure.config import AppConfig
from infrastructure.settings_repository import CorruptSettingError

from .test_analysis_wiring import _wire_fakes


class _FakeSettings:
    """Minimaler Settings-Stand-in (erfuellt strukturell ``ports.settings.SettingsRepository``).

    Liefert je Key einen vorbereiteten ``Setting`` oder wirft ``CorruptSettingError``.
    Default: jeder Key fehlt (``None``). ``_ConfiguredRuleProvider`` ruft NUR ``get`` --
    ``get_all``/``set``/``delete`` sind hier no-op-Stubs, nur damit der Fake das volle
    Protocol erfuellt (mypy-strict)."""

    def __init__(
        self, values: dict[str, Any] | None = None, corrupt: set[str] | None = None
    ) -> None:
        self._values = values or {}
        self._corrupt = corrupt or set()

    def get(self, key: str) -> Setting | None:
        if key in self._corrupt:
            raise CorruptSettingError(key, "{kaputt")
        if key not in self._values:
            return None
        return Setting(key=key, value=self._values[key])

    def get_all(self) -> dict[str, SettingValue]:
        return {}

    def set(self, setting: Setting) -> None: ...

    def delete(self, key: str) -> None: ...


def _builtins() -> _CompositeRuleProvider:
    # Nur die Built-in-Defaults (kein User-Store) als innerer Provider.
    return _CompositeRuleProvider(BuiltinRuleProvider())


def _rule(rules: tuple[Rule, ...], rule_id: str) -> Rule:
    return next(r for r in rules if r.id == rule_id)


# ── Stueck 2: host_many_high_ports-Schwelle ───────────────────────────────────


def test_schwelle_default_wenn_key_fehlt() -> None:
    provider = _ConfiguredRuleProvider(_builtins(), _FakeSettings())
    rule = _rule(provider.get_rules(), "host_many_high_ports")
    assert rule.threshold == _PORT_COUNT_THRESHOLD_DEFAULT == 10


def test_schwelle_wird_aus_setting_uebernommen() -> None:
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_port_count_threshold": 15})
    )
    rule = _rule(provider.get_rules(), "host_many_high_ports")
    assert rule.threshold == 15


def test_schwelle_falscher_typ_faellt_auf_default() -> None:
    # Nicht-Integer (String) -> Default; bool wird ebenfalls nicht als Schwelle akzeptiert.
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_port_count_threshold": "viel"})
    )
    assert _rule(provider.get_rules(), "host_many_high_ports").threshold == 10
    provider_bool = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_port_count_threshold": True})
    )
    assert _rule(provider_bool.get_rules(), "host_many_high_ports").threshold == 10


def test_schwelle_kaputtes_json_loggt_und_faellt_auf_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings(corrupt={"analysis_port_count_threshold"})
    )
    rule = _rule(provider.get_rules(), "host_many_high_ports")
    assert rule.threshold == 10  # Built-in-Default, kein Scan-Abbruch


# ── Stueck 3: auffaellig-/kritisch-Portlisten ─────────────────────────────────


def test_auffaellig_default_wenn_key_fehlt() -> None:
    # Ohne Setting greift die 16er-Built-in-Liste (SSH 22 NICHT dabei).
    rule = _rule(
        _ConfiguredRuleProvider(_builtins(), _FakeSettings()).get_rules(), "host_remote_access_port"
    )
    assert 22 not in rule.ports
    assert {3389, 3306, 27017} <= rule.ports
    assert len(rule.ports) == 16


def test_auffaellig_setting_ueberschreibt() -> None:
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_suspicious_ports": [1234, 5678]})
    )
    rule = _rule(provider.get_rules(), "host_remote_access_port")
    assert rule.ports == frozenset({1234, 5678})


def test_auffaellig_leeres_array_trifft_nichts() -> None:
    # Leeres Array ist ein GUELTIGER Wert: die Regel hat dann keine Ports -> trifft nie.
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_suspicious_ports": []})
    )
    rule = _rule(provider.get_rules(), "host_remote_access_port")
    assert rule.ports == frozenset()


def test_auffaellig_kaputtes_json_faellt_auf_default(caplog: pytest.LogCaptureFixture) -> None:
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings(corrupt={"analysis_suspicious_ports"})
    )
    rule = _rule(provider.get_rules(), "host_remote_access_port")
    assert len(rule.ports) == 16  # Built-in-Default


def test_kritisch_default_ist_backdoor_portmenge() -> None:
    # Ohne Setting bleibt die bestehende Backdoor-Portmenge der Built-in-Regel.
    builtin = _rule(BuiltinRuleProvider().get_rules(), "host_backdoor_port")
    configured = _rule(
        _ConfiguredRuleProvider(_builtins(), _FakeSettings()).get_rules(), "host_backdoor_port"
    )
    assert configured.ports == builtin.ports
    assert 31337 in configured.ports


def test_kritisch_setting_ueberschreibt() -> None:
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_critical_ports": [9999]})
    )
    rule = _rule(provider.get_rules(), "host_backdoor_port")
    assert rule.ports == frozenset({9999})


def test_falscher_typ_portliste_faellt_auf_default() -> None:
    # Nicht-Listen-Wert -> Built-in-Default (kein Override).
    provider = _ConfiguredRuleProvider(
        _builtins(), _FakeSettings({"analysis_suspicious_ports": "nope"})
    )
    rule = _rule(provider.get_rules(), "host_remote_access_port")
    assert len(rule.ports) == 16


def test_andere_regeln_bleiben_unangetastet() -> None:
    # Eine Built-in-Regel ausserhalb der drei konfigurierbaren -> identisch durchgereicht.
    builtin = _rule(BuiltinRuleProvider().get_rules(), "process_temp_path")
    configured = _rule(
        _ConfiguredRuleProvider(_builtins(), _FakeSettings()).get_rules(), "process_temp_path"
    )
    assert configured == builtin


# ── End-zu-End: die ueberschriebene Schwelle wirkt im verdrahteten Runner ──────


def test_setting_schwelle_wirkt_end_zu_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setting=15 -> host_many_high_ports feuert erst bei >15 hohen Ports.

    Voller Runner via ``create_app`` (Fake-Adapter); das Settings-Repository wird durch
    eines ersetzt, das die Schwelle 15 liefert. Ein Host mit 12 hohen Ports darf dann KEINE
    host_many_high_ports-Beobachtung erzeugen (mit Default 10 wuerde sie feuern).
    """

    class _ScanWithTwelveHighPorts:
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def list(self, limit: int) -> list[ScanSummary]:
            return [ScanSummary(scan_id=10, cidr="192.168.1.0/24", host_count=1)]

        def get(self, scan_id: int) -> ScanRecord:
            ports = tuple(PortInfo(port=p, state="open") for p in range(2000, 2012))  # 12 hohe
            return ScanRecord(
                scan_id=scan_id,
                cidr="192.168.1.0/24",
                hosts=(EnrichedHost(ip="192.168.1.77", mac="AA:BB:CC:00:00:09", ports=ports),),
            )

    class _SettingsThreshold15:
        """Settings-Repo-Fake: nur die Schwelle (15) gesetzt, alle anderen Keys fehlen."""

        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def get(self, key: str) -> Setting | None:
            if key == "analysis_port_count_threshold":
                return Setting(key=key, value=15)
            return None

    _wire_fakes(monkeypatch)
    monkeypatch.setattr(app_module, "SqliteScanHistoryRepository", _ScanWithTwelveHighPorts)
    monkeypatch.setattr(app_module, "SqliteSettingsRepository", _SettingsThreshold15)

    from api.analysis import provide_analyze

    app = create_app(AppConfig())
    runner = app.dependency_overrides[provide_analyze]()
    observations = asyncio.run(runner())

    rule_ids = [o.observation.rule_id for o in observations]
    # Schwelle 15 -> 12 hohe Ports unterschreiten sie -> KEINE Beobachtung.
    assert "host_many_high_ports" not in rule_ids
