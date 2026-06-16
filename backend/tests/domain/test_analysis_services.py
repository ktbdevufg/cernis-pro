"""Tests fuer das Port->Service-Mapping der analysis-Domaene (ADR 0027, Stueck 1).

Reine Daten + ``service_for_port``-Lookup: bekannte Ports -> erwarteter Name, unbekannter
Port -> ``None``, ``None`` -> ``None``. Framework-frei, kein I/O.
"""

import pytest

from domain.analysis import SERVICE_BY_PORT, service_for_port


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (22, "ssh"),
        (80, "http"),
        (443, "https"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgresql"),
        (6379, "redis"),
        (27017, "mongodb"),
        (51820, "wireguard"),
        (445, "microsoft-ds"),
    ],
)
def test_bekannte_ports_liefern_erwarteten_service(port: int, expected: str) -> None:
    assert service_for_port(port) == expected


def test_unbekannter_port_liefert_none() -> None:
    # 49152 (dynamischer/ephemerer Bereich) ist bewusst nicht kuratiert.
    assert service_for_port(49152) is None


def test_none_port_liefert_none() -> None:
    # Kein Port -> kein Service (kein Fehler).
    assert service_for_port(None) is None


def test_mapping_ist_breit_genug() -> None:
    # Der Auftrag verlangt ~80-120 kuratierte Eintraege; Untergrenze defensiv pruefen.
    assert len(SERVICE_BY_PORT) >= 80


def test_mapping_werte_sind_knappe_strings() -> None:
    # Jeder Eintrag: int-Port im gueltigen Bereich -> nicht-leerer Service-String.
    for port, service in SERVICE_BY_PORT.items():
        assert isinstance(port, int)
        assert 1 <= port <= 65535
        assert isinstance(service, str)
        assert service != ""
