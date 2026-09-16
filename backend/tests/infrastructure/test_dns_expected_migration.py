"""Tests der Einmal-Migration ``dns_expected_servers`` -> Vertrauens-Tabelle (S62 L7a).

Laeuft gegen ECHTES Schema in einer tmp-DB: die beiden realen Adapter
(``SqliteSettingsRepository`` fuer ``settings``, ``SqliteDnsTrustRepository`` fuer
``dns_trust_servers``) legen ihre Tabellen an, danach arbeitet die Migration darauf --
so belegt der Test die tatsaechliche Spaltenlage, nicht ein nachgebautes Schema.

Belegt die vier fachlichen Zusagen des Auftrags:

(1) Ein Altbestand wird uebernommen und als ``trusted`` hinterlegt; die Kategorie kommt
    ueber das injizierte ``categorize`` (die vorhandene Ableitung), nicht erfunden.
(2) Ein BEREITS VORHANDENER Eintrag behaelt seinen Vertrauens-Zustand -- eine bewusste
    Nutzerentscheidung wiegt schwerer als der Altbestand.
(3) Der alte Schluessel ist danach weg -> der zweite Lauf ist ein Nichtvollzug.
(4) Unbrauchbare Altwerte werden UEBERSPRUNGEN (nicht uebernommen, nicht repariert) und
    reissen die Migration NICHT ab; sie werden getrennt zurueckgegeben, damit der
    Aufrufer sie protokollieren kann (nichts still verschlucken).
"""

import json
import sqlite3
from pathlib import Path

from domain.dns_trust import DnsServerCategory, DnsTrustState, TrustedDnsServer
from infrastructure._dns_expected_migration import (
    LEGACY_EXPECTED_SERVERS_KEY,
    ExpectedServersMigrationResult,
    migrate_expected_servers_to_trust,
)
from infrastructure.dns_trust_repository import SqliteDnsTrustRepository
from infrastructure.settings_repository import SqliteSettingsRepository


def _kategorie_fake(ip: str) -> str:
    """Steht fuer die injizierte, vorhandene Ableitung -- hier bewusst simpel.

    Der Test prueft NICHT die Kategorie-Logik (die hat ihre eigenen Tests in
    ``domain.dns_trust``), sondern DASS die Migration die injizierte Ableitung nutzt
    und ihr Ergebnis wegschreibt.
    """
    return str(DnsServerCategory.GATEWAY if ip.endswith(".1") else DnsServerCategory.UNKNOWN)


def _vorbereiten(tmp_path: Path, altbestand: object | None) -> Path:
    """Legt eine tmp-DB mit beiden echten Schemata an; optional mit Alt-Schluessel."""
    db_path = tmp_path / "cernis.db"
    SqliteSettingsRepository(db_path)
    SqliteDnsTrustRepository(db_path)
    if altbestand is not None:
        conn = sqlite3.connect(db_path)
        with conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                (LEGACY_EXPECTED_SERVERS_KEY, json.dumps(altbestand)),
            )
        conn.close()
    return db_path


def _migrieren(db_path: Path, now: float = 100.0) -> ExpectedServersMigrationResult:
    """Fuehrt die Migration in einer eigenen Transaktion aus (wie der Composition Root)."""
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            return migrate_expected_servers_to_trust(conn, _kategorie_fake, now)
    finally:
        conn.close()


def _servers(db_path: Path) -> dict[str, tuple[str, str]]:
    """Die Vertrauens-Tabelle als ``{ip: (category, trust_state)}``."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT ip, category, trust_state FROM dns_trust_servers").fetchall()
    finally:
        conn.close()
    return {ip: (category, trust_state) for ip, category, trust_state in rows}


def _schluessel_vorhanden(db_path: Path) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM settings WHERE key = ?", (LEGACY_EXPECTED_SERVERS_KEY,)
        ).fetchone()
    finally:
        conn.close()
    return row is not None


# ── (1) Uebernahme des Altbestands ────────────────────────────────────────────


def test_altbestand_wird_als_vertraut_uebernommen(tmp_path: Path) -> None:
    db_path = _vorbereiten(tmp_path, ["192.168.1.1", "192.168.1.53"])

    ergebnis = _migrieren(db_path)

    assert ergebnis.ran is True
    assert sorted(ergebnis.migrated) == ["192.168.1.1", "192.168.1.53"]
    assert _servers(db_path) == {
        # Kategorie aus der injizierten Ableitung, Zustand trusted (stand in "erwartet").
        "192.168.1.1": ("gateway", "trusted"),
        "192.168.1.53": ("unknown", "trusted"),
    }


def test_uebernommene_zeile_ist_vollstaendig_lesbar(tmp_path: Path) -> None:
    """Die geschriebene Zeile muss ueber den echten Adapter zurueckkommen (Enum-Round-trip)."""
    db_path = _vorbereiten(tmp_path, ["10.0.0.1"])

    _migrieren(db_path, now=1234.5)

    server = SqliteDnsTrustRepository(db_path).get("10.0.0.1")
    assert server is not None
    assert server.trust_state is DnsTrustState.TRUSTED
    assert server.category is DnsServerCategory.GATEWAY
    assert server.first_seen == 1234.5
    assert server.last_seen == 1234.5
    assert server.expected_rank == 0
    assert server.is_platform_placeholder is False


def test_ipv6_wird_kanonisch_geschrieben(tmp_path: Path) -> None:
    """Eine abweichend geschriebene IPv6 landet in ihrer kanonischen Form."""
    db_path = _vorbereiten(tmp_path, ["2001:0DB8:0000:0000:0000:0000:0000:0001"])

    ergebnis = _migrieren(db_path)

    assert ergebnis.migrated == ["2001:db8::1"]
    assert "2001:db8::1" in _servers(db_path)


# ── (2) Bestehende Nutzerentscheidung schlaegt den Altbestand ─────────────────


def test_bestehender_eintrag_wird_nicht_ueberschrieben(tmp_path: Path) -> None:
    """Ein abgelehnter Server bleibt abgelehnt -- der Altbestand hebt das NICHT auf."""
    db_path = _vorbereiten(tmp_path, ["192.168.1.53"])
    SqliteDnsTrustRepository(db_path).upsert(
        TrustedDnsServer(
            ip="192.168.1.53",
            category=DnsServerCategory.LOCAL_PRIVATE,
            first_seen=5.0,
            last_seen=5.0,
            trust_state=DnsTrustState.REJECTED,
            display_name="Pi-hole",
        )
    )

    ergebnis = _migrieren(db_path)

    assert ergebnis.migrated == []
    assert ergebnis.kept == ["192.168.1.53"]
    server = SqliteDnsTrustRepository(db_path).get("192.168.1.53")
    assert server is not None
    # VOLLSTAENDIG unangetastet -- Zustand, Kategorie, Zeiten und Name.
    assert server.trust_state is DnsTrustState.REJECTED
    assert server.category is DnsServerCategory.LOCAL_PRIVATE
    assert server.first_seen == 5.0
    assert server.last_seen == 5.0
    assert server.display_name == "Pi-hole"


def test_bestehender_neutraler_eintrag_bleibt_neutral(tmp_path: Path) -> None:
    """Auch ein NEUTRALer Bestand wird nicht auf trusted gehoben (keine stille Wertung)."""
    db_path = _vorbereiten(tmp_path, ["203.0.113.9"])
    SqliteDnsTrustRepository(db_path).upsert(
        TrustedDnsServer(
            ip="203.0.113.9",
            category=DnsServerCategory.UNKNOWN,
            first_seen=5.0,
            last_seen=5.0,
            trust_state=DnsTrustState.NEUTRAL,
        )
    )

    _migrieren(db_path)

    server = SqliteDnsTrustRepository(db_path).get("203.0.113.9")
    assert server is not None
    assert server.trust_state is DnsTrustState.NEUTRAL


# ── (3) Zweiter Lauf ist ein Nichtvollzug ─────────────────────────────────────


def test_schluessel_ist_nach_der_uebernahme_weg(tmp_path: Path) -> None:
    db_path = _vorbereiten(tmp_path, ["192.168.1.1"])

    _migrieren(db_path)

    assert _schluessel_vorhanden(db_path) is False


def test_zweiter_lauf_ist_nichtvollzug(tmp_path: Path) -> None:
    """Beim zweiten Start passiert NICHTS -- der Guard ist der fehlende Schluessel."""
    db_path = _vorbereiten(tmp_path, ["192.168.1.1"])
    _migrieren(db_path)
    vorher = _servers(db_path)

    zweiter = _migrieren(db_path)

    assert zweiter.ran is False
    assert zweiter.migrated == []
    assert _servers(db_path) == vorher


def test_zweiter_lauf_hebt_zurueckgenommenes_vertrauen_nicht_wieder_an(
    tmp_path: Path,
) -> None:
    """Nimmt der Nutzer das Vertrauen zurueck, holt es der Altbestand NICHT zurueck."""
    db_path = _vorbereiten(tmp_path, ["192.168.1.53"])
    _migrieren(db_path)
    SqliteDnsTrustRepository(db_path).set_trust("192.168.1.53", DnsTrustState.REJECTED, now=200.0)

    _migrieren(db_path)

    server = SqliteDnsTrustRepository(db_path).get("192.168.1.53")
    assert server is not None
    assert server.trust_state is DnsTrustState.REJECTED


def test_frische_db_ohne_schluessel_ist_nichtvollzug(tmp_path: Path) -> None:
    """Der Regelfall auf dieser Maschine: der alte Schluessel existiert gar nicht."""
    db_path = _vorbereiten(tmp_path, None)

    ergebnis = _migrieren(db_path)

    assert ergebnis.ran is False
    assert _servers(db_path) == {}


# ── (4) Unbrauchbare Altwerte ─────────────────────────────────────────────────


def test_unbrauchbare_werte_werden_uebersprungen_nicht_uebernommen(
    tmp_path: Path,
) -> None:
    """Muell bricht die Migration NICHT ab und landet NICHT in der Tabelle."""
    db_path = _vorbereiten(
        tmp_path,
        [
            "192.168.1.1",  # gueltig
            "",  # leer
            "   ",  # nur Leerraum
            "1:2",  # halbes IPv6-Fragment (kam durch die alte Grobpruefung)
            "999.1.1.1",  # Oktett ausserhalb 0-255
            "pihole.fritz.box",  # Hostname, keine Adresse
            42,  # gar keine Zeichenkette
            "10.0.0.1",  # gueltig -- MUSS trotz des Muells davor ankommen
        ],
    )

    ergebnis = _migrieren(db_path)

    assert sorted(ergebnis.migrated) == ["10.0.0.1", "192.168.1.1"]
    # Nichts still verschluckt: jeder uebersprungene Rohwert kommt zurueck.
    assert sorted(ergebnis.skipped) == sorted(
        ["", "   ", "1:2", "999.1.1.1", "pihole.fritz.box", "42"]
    )
    assert sorted(_servers(db_path)) == ["10.0.0.1", "192.168.1.1"]


def test_altbestand_nur_aus_muell_loescht_den_schluessel_trotzdem(tmp_path: Path) -> None:
    """Auch wenn nichts uebernehmbar war: der tote Schluessel verschwindet."""
    db_path = _vorbereiten(tmp_path, ["nur-muell"])

    ergebnis = _migrieren(db_path)

    assert ergebnis.migrated == []
    assert ergebnis.skipped == ["nur-muell"]
    assert _servers(db_path) == {}
    assert _schluessel_vorhanden(db_path) is False


def test_wert_ist_keine_liste_wird_gemeldet_und_geloescht(tmp_path: Path) -> None:
    """Ein per API beschriebener Nicht-Listen-Wert reisst den Start nicht ab."""
    db_path = _vorbereiten(tmp_path, {"unerwartet": "objekt"})

    ergebnis = _migrieren(db_path)

    assert ergebnis.ran is True
    assert ergebnis.migrated == []
    assert ergebnis.skipped != []  # der Rohwert wird gemeldet, nicht verschluckt
    assert _servers(db_path) == {}
    assert _schluessel_vorhanden(db_path) is False


def test_leere_altliste_uebernimmt_nichts_und_raeumt_auf(tmp_path: Path) -> None:
    """Der haeufige Fall "Liste angelegt, aber nie gefuellt": nichts zu uebernehmen."""
    db_path = _vorbereiten(tmp_path, [])

    ergebnis = _migrieren(db_path)

    assert ergebnis.ran is True
    assert ergebnis.migrated == []
    assert ergebnis.skipped == []
    assert _servers(db_path) == {}
    assert _schluessel_vorhanden(db_path) is False
