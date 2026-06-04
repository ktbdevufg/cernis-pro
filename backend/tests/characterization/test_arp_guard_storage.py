"""Characterization-Contract des arp_guard-Altcode (``modules/arp_guard.py``).

Friert den Ist-Zustand VOR der SEC.2+-Migration ein (Strangler-Fig). Getestet wird
``modules.arp_guard`` AS-IS gegen eine temporaere DB: ``DB_PATH`` wird AM MODUL-NAMESPACE
umgebogen (``monkeypatch.setattr(arp_guard, "DB_PATH", ...)``), NICHT via Env -- exakt das
Muster aus ``test_alerting_storage`` / ``test_monitoring_storage`` (``from modules.db_path
import DB_PATH`` bindet den Wert beim Import als String, ein spaetes Env-Setzen wirkt nicht
mehr).

Fremd-Calls werden GEMOCKT (der Charakterisierer braucht keine echte ARP-Tabelle):
  * ``get_arp_table`` (aus ``modules.discovery``, scanning-Domaene) -> liefert die
    Test-{ip: mac}-Tabelle.
  * ``lookup_vendor`` (aus ``modules.vendor``, scanning-Domaene) -> deterministischer
    Vendor je MAC. Beide am ``arp_guard``-Namespace gepatcht.

────────────────────────────────────────────────────────────────────────────
EINGEFRORENE AS-IS-VERHALTEN (duerfen in SEC.2+ NICHT still kippen)
────────────────────────────────────────────────────────────────────────────

1. ARP-ALERTS = MOMENTAUFNAHME, NICHT HISTORIE (Befund E.1 -- der WICHTIGSTE).
   ``_scan_arp_sync`` ruft ``_clear_alerts()`` (arp_guard.py:149) VOR jedem Scan ->
   nach ``scan_arp_once`` enthaelt ``arp_alerts`` NUR die Alerts dieses Scans, der
   vorige Scan ist geloescht. ``get_arp_alerts(limit)`` hat zwar ``ORDER BY ts DESC
   LIMIT ?``, aber der ``limit``-Parameter ist praktisch wirkungslos, weil clear die
   Historie verhindert. >> AS-IS, irrefuehrender Name (``get_arp_alerts`` suggeriert
   Historie). Ob arp_alerts echte Historie werden soll, ist Phase-4 / Produkt-
   entscheidung -- NICHT SEC. Hier nur eingefroren.

2. ``new_device`` ERZEUGT KEINEN ALERT (Abweichung vom Docstring!).
   Der ``ArpAlert``-Docstring (arp_guard.py:29) listet ``alert_type`` "new_device" als
   moeglichen Wert, ABER ``_scan_arp_sync`` erzeugt fuer eine neue IP NUR einen
   ``_save_baseline``-Eintrag, KEINEN Alert (arp_guard.py:201-203, Kommentar "New
   device -- just log to baseline"). ``_scan_arp_sync`` produziert real nur die zwei
   Typen ``ip_conflict`` und ``mac_changed``. "new_device" ist toter alert_type-Wert.
   >> AS-IS eingefroren: neue IP -> baseline-Zeile, KEIN Alert.

3. SEVERITY-VERTRAEGE (AS-IS):
   * ``ip_conflict`` -> IMMER "high" (arp_guard.py:169).
   * ``mac_changed`` -> "high" wenn ``old_vendor`` gesetzt UND neuer vendor != old_vendor;
     sonst "medium" (arp_guard.py:186). Heisst: kein alter vendor bekannt -> "medium";
     vendor unveraendert -> "medium"; vendor real gewechselt -> "high".

4. VENDOR-LOOKUP-INKONSISTENZ (AS-IS, subtil):
   * ``ip_conflict`` ruft ``lookup_vendor(mac)`` mit dem bereits ge-upper-ten Key aus
     ``mac_to_ips`` (arp_guard.py:163) -- dort ist ``mac`` schon ``mac_upper``.
   * ``mac_changed`` ruft ``lookup_vendor(mac_upper)`` (arp_guard.py:179).
   Beide effektiv upper. Der Mock ist case-insensitiv gehalten, damit dieser Pfad
   nicht zufaellig den Test traegt.

5. MAC-SPEICHERUNG vs. ALERT-FELDER (AS-IS):
   ``_save_baseline`` speichert ``mac_upper`` (arp_guard.py:200/203), aber das
   ``old_mac``-Feld eines ``mac_changed``-Alerts nutzt das ROH gespeicherte
   ``baseline[ip].mac`` (arp_guard.py:190) -- also den upper-Wert aus der DB.
   ``new_mac`` ist die rohe (ungeupperte) current-MAC (arp_guard.py:191).

6. ZEITKONVENTION (AS-IS, wie alert_history das Doppelmuster M.8):
   * ``arp_baseline``: ``first_seen``/``last_seen`` = epoch-float (REAL).
   * ``arp_alerts``: ``ts`` = epoch-float (REAL) UND ``datetime`` = ISO-TEXT
     ("%Y-%m-%d %H:%M:%S") -- BEIDE Spalten parallel.

7. ``clear_baseline`` leert NUR ``arp_baseline`` (arp_guard.py:131-136); ``arp_alerts``
   bleibt unberuehrt. AS-IS.

Die S3-stillen-Fallbacks von cve/tls/default_creds (E.2-E.5) gehoeren NICHT hierher
(SEC.1b / SEC.4). arp_guard selbst hat keine stillen except-Faenge -- der einzige
"irrefuehrende" Befund ist die Momentaufnahme (E.1), oben als Vertrag 1 eingefroren.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def arp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """arp_guard-Modul mit tmp-DB; Fremd-Calls noch NICHT gemockt (s. arp_scanner)."""
    from modules import arp_guard as arp_mod

    monkeypatch.setattr(arp_mod, "DB_PATH", str(tmp_path / "cernis.db"))
    return arp_mod


def _make_vendor_lookup() -> Any:
    """Deterministischer, case-insensitiver Vendor je MAC-Praefix (OUI-aehnlich)."""
    table = {
        "AA:AA:AA": "AcmeCorp",
        "BB:BB:BB": "BetaInc",
        "CC:CC:CC": "GammaLtd",
    }

    def lookup(mac: str) -> str:
        return table.get(mac.upper()[:8], "Unknown")

    return lookup


@pytest.fixture
def arp_scanner(
    arp: Any, monkeypatch: pytest.MonkeyPatch
) -> tuple[Callable[[], list[Any]], Callable[[dict[str, str]], None]]:
    """Liefert (run, set_table): set_table({ip: mac}) stellt die gemockte ARP-Tabelle,
    run() ruft den synchronen Scan-Pfad ``_scan_arp_sync`` und gibt die Alert-Liste."""
    current: dict[str, str] = {}

    def fake_arp_table() -> dict[str, str]:
        return dict(current)

    monkeypatch.setattr(arp, "get_arp_table", fake_arp_table)
    monkeypatch.setattr(arp, "lookup_vendor", _make_vendor_lookup())

    def set_table(table: dict[str, str]) -> None:
        nonlocal current
        current = dict(table)

    def run() -> list[Any]:
        result: list[Any] = arp._scan_arp_sync()
        return result

    return run, set_table


# ── _init_arp_db: idempotent, beide Tabellen ──────────────────


def test_init_arp_db_idempotent_creates_both_tables(arp: Any) -> None:
    import sqlite3

    arp._init_arp_db()
    arp._init_arp_db()  # 2x -> kein Fehler

    conn = sqlite3.connect(arp.DB_PATH)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "arp_baseline" in names
    assert "arp_alerts" in names


def test_arp_baseline_schema_columns(arp: Any) -> None:
    import sqlite3

    arp._init_arp_db()
    conn = sqlite3.connect(arp.DB_PATH)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(arp_baseline)")}
    conn.close()
    assert cols == {"ip", "mac", "vendor", "first_seen", "last_seen"}


def test_arp_alerts_schema_has_double_time_columns(arp: Any) -> None:
    # Vertrag 6: arp_alerts fuehrt ts (REAL epoch) UND datetime (TEXT ISO) parallel.
    import sqlite3

    arp._init_arp_db()
    conn = sqlite3.connect(arp.DB_PATH)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(arp_alerts)")}
    conn.close()
    assert "ts" in cols
    assert "datetime" in cols
    assert {
        "alert_type",
        "ip",
        "old_mac",
        "new_mac",
        "old_vendor",
        "new_vendor",
        "severity",
        "message",
    } <= cols


# ── Baseline: erste Sichtung / Update ─────────────────────────


def test_first_sighting_creates_baseline_row_first_eq_last(arp_scanner: Any, arp: Any) -> None:
    run, set_table = arp_scanner
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})
    run()

    rows = arp.get_arp_baseline()
    assert len(rows) == 1
    r = rows[0]
    assert r["ip"] == "192.168.1.10"
    assert r["mac"] == "AA:AA:AA:11:11:11"  # mac_upper gespeichert
    assert r["vendor"] == "AcmeCorp"
    # erste Sichtung: first_seen == last_seen (Vertrag 6, beide REAL).
    assert r["first_seen"] == r["last_seen"]
    assert isinstance(r["first_seen"], float)


def test_resight_updates_last_seen_keeps_first_seen(arp_scanner: Any, arp: Any) -> None:
    run, set_table = arp_scanner
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})
    run()
    first = arp.get_arp_baseline()[0]["first_seen"]

    # gleiche IP/MAC erneut sehen -> last_seen aktualisiert, first_seen bleibt.
    run()
    r = arp.get_arp_baseline()[0]
    assert r["first_seen"] == first
    assert r["last_seen"] >= first


# ── ERKENNUNG: ip_conflict (feuert / Gegenprobe) ──────────────


def test_ip_conflict_fires_on_shared_mac(arp_scanner: Any) -> None:
    run, set_table = arp_scanner
    # Dieselbe MAC auf zwei IPs -> ip_conflict.
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    alerts = run()
    conflicts = [a for a in alerts if a.alert_type == "ip_conflict"]
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.severity == "high"  # Vertrag 3: immer high
    assert c.new_mac == "BB:BB:BB:22:22:22"
    assert c.new_vendor == "BetaInc"
    assert "192.168.1.10" in c.ip and "192.168.1.11" in c.ip


def test_ip_conflict_gegenprobe_unique_macs_no_conflict(arp_scanner: Any) -> None:
    run, set_table = arp_scanner
    # Jede IP eigene MAC -> KEIN ip_conflict.
    set_table(
        {
            "192.168.1.10": "AA:AA:AA:11:11:11",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    alerts = run()
    assert [a for a in alerts if a.alert_type == "ip_conflict"] == []


# ── ERKENNUNG: mac_changed (feuert / Gegenprobe + severity) ───


def test_mac_changed_fires_with_high_when_vendor_changes(arp_scanner: Any) -> None:
    run, set_table = arp_scanner
    # Baseline anlegen.
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})  # AcmeCorp
    run()
    # MAC wechselt zu anderem Vendor -> mac_changed, severity high.
    set_table({"192.168.1.10": "BB:BB:BB:22:22:22"})  # BetaInc
    alerts = run()
    changed = [a for a in alerts if a.alert_type == "mac_changed"]
    assert len(changed) == 1
    c = changed[0]
    assert c.severity == "high"  # old_vendor gesetzt UND verschieden
    assert c.ip == "192.168.1.10"
    assert c.old_mac == "AA:AA:AA:11:11:11"  # Vertrag 5: upper aus DB
    assert c.new_mac == "BB:BB:BB:22:22:22"
    assert c.old_vendor == "AcmeCorp"
    assert c.new_vendor == "BetaInc"


def test_mac_changed_medium_when_vendor_same(arp_scanner: Any) -> None:
    run, set_table = arp_scanner
    # Baseline: AcmeCorp-Praefix.
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})
    run()
    # neue MAC, ABER gleicher Vendor (gleiches OUI-Praefix) -> severity medium.
    set_table({"192.168.1.10": "AA:AA:AA:99:99:99"})  # weiterhin AcmeCorp
    alerts = run()
    changed = [a for a in alerts if a.alert_type == "mac_changed"]
    assert len(changed) == 1
    assert changed[0].severity == "medium"  # vendor unveraendert -> medium


def test_mac_changed_gegenprobe_same_mac_no_alert(arp_scanner: Any) -> None:
    run, set_table = arp_scanner
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})
    run()
    # identische MAC erneut -> KEIN mac_changed.
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})
    alerts = run()
    assert [a for a in alerts if a.alert_type == "mac_changed"] == []


# ── ERKENNUNG: new_device erzeugt KEINEN Alert (Vertrag 2) ────
#
# LATENTE NAHT-NOTIZ (security -> alerting, DF1-Nachzuegler -- NICHT jetzt verdrahten):
# ``modules/arp_guard.py:29`` deklariert ``alert_type: str  # ... | "new_device"`` als
# dokumentierten Wert, ABER keine ArpAlert-Konstruktion schreibt ihn je (die einzigen
# zwei sind ip_conflict @165 und mac_changed @188; der neue-IP-Pfad @201-203 ruft nur
# _save_baseline). Toter Wert. Korrespondierend hat ``domain/alerting/models.py``
# ``RULE_TYPE_NEW_DEVICE`` als ebenfalls ungenutzte Konstante. GENAU HIER (neue-IP-Pfad)
# wuerde eine kuenftige security->alerting-Verdrahtung einen new_device-Alert feuern.
# Diese zwei Tests frieren den Ist-Zustand "kein new_device-Alert" ein -- der spaetere
# Trigger-Schritt findet die Naht ueber diese Notiz. SEC verdrahtet sie NICHT.


def test_new_device_creates_baseline_but_no_alert(arp_scanner: Any, arp: Any) -> None:
    run, set_table = arp_scanner
    # Voellig neue IP -> nur baseline-Eintrag, KEIN Alert (Vertrag 2).
    set_table({"192.168.1.50": "CC:CC:CC:33:33:33"})
    alerts = run()
    # Alert-NEIN: weder zurueckgegeben ...
    assert alerts == []  # kein "new_device"-Alert
    # ... noch persistiert (ein Bug, der heimlich einen Alert schreibt, faellt hier auf).
    assert arp.get_arp_alerts() == []
    # baseline-JA: die neue IP IST eingetragen (sonst koennte ein Bug beides
    # unterdruecken und der Test waere trotzdem gruen).
    base = arp.get_arp_baseline()
    assert len(base) == 1
    assert base[0]["ip"] == "192.168.1.50"
    assert base[0]["mac"] == "CC:CC:CC:33:33:33"
    assert base[0]["vendor"] == "GammaLtd"


def test_no_alert_type_new_device_ever_emitted(arp_scanner: Any, arp: Any) -> None:
    # Gegenprobe zur Docstring-Behauptung: kein Scan-Pfad erzeugt alert_type="new_device".
    run, set_table = arp_scanner
    set_table({"192.168.1.50": "CC:CC:CC:33:33:33"})
    run()
    set_table({"192.168.1.51": "AA:AA:AA:11:11:11"})
    run()
    stored = arp.get_arp_alerts()
    assert all(a["alert_type"] != "new_device" for a in stored)


# ── MOMENTAUFNAHME-VERTRAG (E.1) -- der Kern ──────────────────


def test_alerts_are_snapshot_only_second_scan_visible(arp_scanner: Any, arp: Any) -> None:
    """Vertrag 1 (Kern): _clear_alerts loescht vor jedem Scan. Scan A erzeugt Alert X,
    Scan B (andere Bedingung) erzeugt Alert Y -> get_arp_alerts zeigt NUR Y, X ist weg.
    """
    run, set_table = arp_scanner

    # Scan A: ip_conflict (Alert X).
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    alerts_a = run()
    assert any(a.alert_type == "ip_conflict" for a in alerts_a)
    stored_a = arp.get_arp_alerts()
    assert len(stored_a) == 1
    assert stored_a[0]["alert_type"] == "ip_conflict"

    # Scan B: kein Konflikt mehr, aber MAC-Wechsel auf .10 (Alert Y).
    # (.10 + .11 waren oben mit BB-MAC als baseline gespeichert.)
    set_table(
        {
            "192.168.1.10": "AA:AA:AA:11:11:11",  # war BB -> mac_changed
            "192.168.1.11": "BB:BB:BB:22:22:22",  # unveraendert -> kein Alert
        }
    )
    alerts_b = run()
    assert any(a.alert_type == "mac_changed" for a in alerts_b)

    # Momentaufnahme: nur Scan-B-Alerts sichtbar, der ip_conflict aus Scan A ist WEG.
    stored_b = arp.get_arp_alerts()
    assert all(a["alert_type"] != "ip_conflict" for a in stored_b)
    assert any(a["alert_type"] == "mac_changed" for a in stored_b)


def test_clean_scan_clears_previous_alerts(arp_scanner: Any, arp: Any) -> None:
    """Verschaerfung des Momentaufnahme-Vertrags: Scan A erzeugt einen Alert, ein spaeterer
    voellig sauberer Scan (jede IP auf ihrer baseline-MAC, eindeutig) -> 0 gespeicherte
    Alerts. Beweist, dass _clear_alerts den Vor-Scan-Alert auch dann entfernt, wenn der
    saubere Scan selbst nichts feuert.

    Hinweis AS-IS: ip_conflict ist TABELLEN-basiert (gleiche MAC auf >1 IP in der
    aktuellen Tabelle), nicht baseline-basiert -- darum braucht der "saubere" Scan
    eindeutige MACs je IP, nicht bloss baseline-Gleichheit.
    """
    run, set_table = arp_scanner

    # Scan A: ip_conflict (BB-MAC auf zwei IPs) -> 1 Alert; baseline kennt danach .10/.11=BB.
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    run()
    assert len(arp.get_arp_alerts()) == 1

    # Zwischen-Scan: .11 auf eindeutige AA umstellen (baseline BB->AA, erzeugt mac_changed).
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",  # baseline BB -> unveraendert
            "192.168.1.11": "AA:AA:AA:11:11:11",  # baseline BB -> mac_changed (Uebergang)
        }
    )
    run()  # baseline danach: .10=BB, .11=AA, MACs eindeutig

    # Sauberer Scan: beide auf ihrer baseline-MAC, eindeutig -> kein conflict, kein change.
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "AA:AA:AA:11:11:11",
        }
    )
    run()
    # clear hat den vorigen mac_changed entfernt, nichts Neues gefeuert.
    assert arp.get_arp_alerts() == []


# ── get_arp_alerts: Form (ORDER BY ts DESC, limit) ────────────


def test_get_arp_alerts_orders_ts_desc_within_one_scan(arp_scanner: Any, arp: Any) -> None:
    # Ein Scan kann mehrere Alerts erzeugen (conflict + mac_changed). Form: ts DESC.
    run, set_table = arp_scanner
    # baseline fuer .10.
    set_table({"192.168.1.10": "AA:AA:AA:11:11:11"})
    run()
    # Scan mit conflict (BB auf 2 IPs) UND mac_changed auf .10 (AA->BB).
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    run()
    stored = arp.get_arp_alerts(limit=50)
    ts_values = [a["ts"] for a in stored]
    assert ts_values == sorted(ts_values, reverse=True)


def test_limit_is_effectively_inert_due_to_clear(arp_scanner: Any, arp: Any) -> None:
    # Selbst limit=1 zeigt alle Alerts EINES Scans nicht weg -- aber die Pointe ist:
    # clear haelt die Gesamtmenge ohnehin klein (nur letzter Scan). Hier: ein Scan mit
    # genau 1 Alert, limit gross -> 1; voriger Scan trotz Alerts unsichtbar.
    run, set_table = arp_scanner
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    run()  # Scan 1: 1 conflict
    set_table({"192.168.1.20": "AA:AA:AA:11:11:11"})  # neue IP, kein Alert
    run()  # Scan 2: 0 Alerts -> clear hat Scan-1-conflict entfernt
    assert arp.get_arp_alerts(limit=1000) == []


# ── get_arp_baseline / clear_baseline ─────────────────────────


def test_get_arp_baseline_ordered_by_ip(arp_scanner: Any, arp: Any) -> None:
    run, set_table = arp_scanner
    set_table(
        {
            "192.168.1.30": "CC:CC:CC:33:33:33",
            "192.168.1.10": "AA:AA:AA:11:11:11",
            "192.168.1.20": "BB:BB:BB:22:22:22",
        }
    )
    run()
    ips = [r["ip"] for r in arp.get_arp_baseline()]
    assert ips == sorted(ips)  # ORDER BY ip


def test_clear_baseline_empties_baseline_only(arp_scanner: Any, arp: Any) -> None:
    # Vertrag 7: clear_baseline leert NUR arp_baseline, arp_alerts bleibt.
    run, set_table = arp_scanner
    set_table(
        {
            "192.168.1.10": "BB:BB:BB:22:22:22",
            "192.168.1.11": "BB:BB:BB:22:22:22",
        }
    )
    run()
    assert len(arp.get_arp_baseline()) == 2
    assert len(arp.get_arp_alerts()) == 1

    arp.clear_baseline()
    assert arp.get_arp_baseline() == []
    # alerts unberuehrt (AS-IS).
    assert len(arp.get_arp_alerts()) == 1
