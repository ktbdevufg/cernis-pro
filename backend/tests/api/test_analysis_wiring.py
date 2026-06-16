"""Tests fuer die ausfallsichere hosts-Projektion des ``_analyze_snapshot``-Runners (B-fix).

Der echte ``_analyze_snapshot``-Runner (Composition Root, via
``dependency_overrides[provide_analyze]`` herausgereicht) wird hier END-zu-END gegen
``create_app`` durchlaufen -- aber mit Fake-Adaptern statt echtem psutil/echter DB
(Muster ``test_fritz_hosts_wiring.py``: ``monkeypatch.setattr(app_module, ...)`` +
``asyncio.run``).

Belegt die Entscheidung A (Ausfallsicherheit der Host-Schicht): wirft das verdrahtete
ScanHistory-Repository bei ``get()`` einen ``CorruptScanError`` (``list(1)`` liefert aber
einen Summary), liefert der Runner TROTZDEM ein Ergebnis -- OHNE
``host_remote_access_port``-Beobachtung und OHNE Absturz; die uebrigen Quellen
(traffic/process) sind unberuehrt. Der intakte Scan (Happy Path) liefert die
host-Beobachtung weiterhin.
"""

import asyncio
from typing import Any, ClassVar

import pytest

import app as app_module
from api.analysis import provide_analyze
from app import create_app
from domain.scanning.models import EnrichedHost, PortInfo, ScanRecord, ScanSummary
from domain.traffic import Connection, Endpoint
from infrastructure.config import AppConfig
from infrastructure.scanning.scan_history import CorruptScanError


class _FakeTrafficAdapter:
    """Liefert EINE Verbindung zu Port 22 -- erzeugt eine ``remote_access_port``-
    Beobachtung (connection-side). Stellt die ``traffic``-Quelle als unberuehrt dar."""

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    async def list_connections(self) -> list[Connection]:
        return [
            Connection(
                l4="tcp",
                status="established",
                local=Endpoint(ip="192.168.1.10", port=54321),
                remote=Endpoint(ip="1.2.3.4", port=22),
                pid=4711,
                app_name="ssh",
            )
        ]


class _FakeProcessAdapter:
    """Liefert keine Prozesse -- die process-Quelle ist hier bewusst leer (nicht
    Gegenstand dieses Tests)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    async def list_processes(self) -> list[Any]:
        return []


class _FakeProcessPermission:
    """Rootless: kein voller Einblick (der kein-Pfad-Tarnverdacht schweigt)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    def is_available(self) -> bool:
        return True

    def check_permission(self) -> dict[str, object]:
        return {"ok": False, "detail": "rootless"}


class _FakeUserRuleRepo:
    """Keine benutzer-eigenen Regeln -- nur die eingebauten Defaults zaehlen."""

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    def get_rules(self) -> tuple[Any, ...]:
        return ()


class _FakeHostHistoryRepo:
    """Fake der analysis-Host-Historie (C.2) -- eine feste Menge bekannter MACs.

    Die Lese-Naht (``_analyze_snapshot``) ruft NUR ``known_macs`` (Bulk-Lesepfad);
    ``record_seen`` ist hier ein no-op (die Lese-Naht schreibt nicht). Default:
    leere Historie (alle Hosts unbekannt) -- die Tests, die die Historie variieren,
    uebergeben ihre eigene MAC-Menge.
    """

    known: ClassVar[set[str]] = set()

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    def known_macs(self) -> set[str]:
        return set(self.known)

    def record_seen(self, mac: str) -> None: ...  # no-op (Lese-Naht schreibt nicht)


def _wire_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ersetzt am app-Import-Ort alle Live-Quellen-Adapter durch Fakes (kein psutil,
    keine echte DB) -- nur das ScanHistory-/Host-Historie-Verhalten variieren die
    Tests selbst. Standard-Host-Historie: leer (alle Hosts unbekannt)."""
    monkeypatch.setattr(app_module, "PsutilTrafficAdapter", _FakeTrafficAdapter)
    monkeypatch.setattr(app_module, "PsutilProcessAdapter", _FakeProcessAdapter)
    monkeypatch.setattr(app_module, "ProcessPermissionAdapter", _FakeProcessPermission)
    monkeypatch.setattr(app_module, "SqliteUserRuleRepository", _FakeUserRuleRepo)
    monkeypatch.setattr(app_module, "SqliteHostHistoryRepository", _FakeHostHistoryRepo)


def _rule_ids(observations: list[Any]) -> list[str]:
    return [o.observation.rule_id for o in observations]


def test_corrupt_latest_scan_skips_hosts_without_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """Korrupter juengster Scan -> kein Absturz, KEINE host_remote_access_port-Beobachtung,
    traffic-Quelle unberuehrt (remote_access_port bleibt)."""

    class _CorruptScanHistoryRepo:
        """list(1) -> ein Summary, get() -> CorruptScanError (Serializer-Fix 3536c7d)."""

        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def list(self, limit: int) -> list[ScanSummary]:
            return [ScanSummary(scan_id=10, cidr="192.168.1.0/24", host_count=1)]

        def get(self, scan_id: int) -> ScanRecord:
            raise CorruptScanError(scan_id, '{"properties": {"k": "v"}}')

    _wire_fakes(monkeypatch)
    monkeypatch.setattr(app_module, "SqliteScanHistoryRepository", _CorruptScanHistoryRepo)

    app = create_app(AppConfig())
    runner = app.dependency_overrides[provide_analyze]()
    observations = asyncio.run(runner())

    rule_ids = _rule_ids(observations)
    # Host-Schicht uebersprungen: KEINE geraeteseitige Fernzugriffs-Beobachtung.
    assert "host_remote_access_port" not in rule_ids
    # Aber die traffic-Quelle ist unberuehrt: die connection-side-Beobachtung kommt.
    assert "remote_access_port" in rule_ids


def test_intact_latest_scan_yields_host_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Happy Path (B-Stand): intakter Scan mit offenem Port 3389 -> host_remote_access_port.

    ADR 0027: SSH 22 ist kein auffaellig-Default-Treffer mehr -- der Scan haelt darum 3389
    (rdp) offen, das in der auffaellig-Default-Liste liegt.
    """

    class _IntactScanHistoryRepo:
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def list(self, limit: int) -> list[ScanSummary]:
            return [ScanSummary(scan_id=10, cidr="192.168.1.0/24", host_count=1)]

        def get(self, scan_id: int) -> ScanRecord:
            return ScanRecord(
                scan_id=scan_id,
                cidr="192.168.1.0/24",
                hosts=(
                    EnrichedHost(
                        ip="192.168.1.50",
                        mac="AA:BB:CC:00:00:01",
                        hostname="nas",
                        ports=(PortInfo(port=3389, state="open"),),
                    ),
                ),
            )

    _wire_fakes(monkeypatch)
    monkeypatch.setattr(app_module, "SqliteScanHistoryRepository", _IntactScanHistoryRepo)

    app = create_app(AppConfig())
    runner = app.dependency_overrides[provide_analyze]()
    observations = asyncio.run(runner())

    rule_ids = _rule_ids(observations)
    # Intakter Scan: die host-seitige Fernzugriffs-Beobachtung ist da.
    assert "host_remote_access_port" in rule_ids
    # Und die traffic-Quelle bleibt ebenfalls vorhanden (beide Quellen).
    assert "remote_access_port" in rule_ids


def test_known_host_not_new_unknown_host_is_new(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lese-Naht (C.2): Historie kennt MAC X, nicht MAC Y -> is_known True fuer X,
    False fuer Y; new_host_seen erscheint NUR fuer Y (echter Neuzugang)."""

    class _TwoHostScanHistoryRepo:
        """Juengster Scan mit zwei Hosts: X (bekannt) und Y (neu). Keine offenen
        Ports -> KEIN host_remote_access_port; isoliert die new_host_seen-Naht."""

        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def list(self, limit: int) -> list[ScanSummary]:
            return [ScanSummary(scan_id=10, cidr="192.168.1.0/24", host_count=2)]

        def get(self, scan_id: int) -> ScanRecord:
            return ScanRecord(
                scan_id=scan_id,
                cidr="192.168.1.0/24",
                hosts=(
                    EnrichedHost(ip="192.168.1.51", mac="AA:BB:CC:00:00:0X", hostname="known"),
                    EnrichedHost(ip="192.168.1.52", mac="AA:BB:CC:00:00:0Y", hostname="neu"),
                ),
            )

    class _HistoryKnowsX(_FakeHostHistoryRepo):
        """Historie kennt nur MAC X -- Y ist neu."""

        known: ClassVar[set[str]] = {"AA:BB:CC:00:00:0X"}

    _wire_fakes(monkeypatch)
    monkeypatch.setattr(app_module, "SqliteScanHistoryRepository", _TwoHostScanHistoryRepo)
    monkeypatch.setattr(app_module, "SqliteHostHistoryRepository", _HistoryKnowsX)

    app = create_app(AppConfig())
    runner = app.dependency_overrides[provide_analyze]()
    observations = asyncio.run(runner())

    # new_host_seen feuert -- und NUR fuer den unbekannten Host Y (subject = dessen ip).
    new_host_obs = [o for o in observations if o.observation.rule_id == "new_host_seen"]
    assert len(new_host_obs) == 1
    assert new_host_obs[0].observation.subject == "192.168.1.52"  # Y, nicht X
