"""Tests fuer die geteilte MAC-Vereinheitlichung der cve-Adapter (``_cve_mac``).

Belegt die schmale Normalisierungsregel (nur Gross-/Kleinschreibung, idempotent,
leer bleibt leer -- S3) und den Rand der Migrations-Weiche: ein unbekannter
Tabellenname bricht LAUT statt still nichts zu tun. Die tabellen-spezifischen
Zusammenfuehrungs-Regeln stehen bei den drei Adapter-Tests, wo sie gegen echtes
Schema laufen.
"""

import sqlite3

import pytest

from infrastructure._cve_mac import migrate_macs_to_upper, normalize_mac_case


def test_hebt_auf_grossschreibung() -> None:
    assert normalize_mac_case("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"


def test_ist_idempotent() -> None:
    einmal = normalize_mac_case("aa:bb:cc:dd:ee:ff")
    assert normalize_mac_case(einmal) == einmal


def test_leere_mac_bleibt_leer() -> None:
    """S3: KEIN Umdeuten einer leeren MAC in irgendeinen Ersatzwert."""
    assert normalize_mac_case("") == ""


def test_trennzeichen_bleiben_unangetastet() -> None:
    """Bewusst NUR die Schreibweise -- keine Trennzeichen-Normalisierung."""
    assert normalize_mac_case("aabb.ccdd.eeff") == "AABB.CCDD.EEFF"
    assert normalize_mac_case("aa-bb-cc-dd-ee-ff") == "AA-BB-CC-DD-EE-FF"


def test_unbekannte_tabelle_bricht_laut() -> None:
    """Ein Tippfehler im Tabellennamen ist ein Programmierfehler, kein stiller No-op."""
    conn = sqlite3.connect(":memory:")
    try:
        with pytest.raises(ValueError, match="Unbekannte cve-Tabelle"):
            migrate_macs_to_upper(conn, "irgendwas_anderes")
    finally:
        conn.close()
