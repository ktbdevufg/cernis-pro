"""Tests der reinen metrics-Format-Funktionen (M.8 Schritt 1) -- OHNE DB.

Gespeist aus handgebauten ``MetricsSnapshot``-Instanzen; die Zeilen-/Feld-Form ist
gegen die Altcode-Referenz (``modules/metrics.py``) verifiziert. HIER wird zugleich
die GEHEILTE v2-Form belegt: ein Snapshot MIT rtt_points (was der M.4-alive-Fix erst
moeglich macht) erzeugt die in v1 toten ``cernis_monitor_*``-/influx-rtt-/HA-state-
Ausgaben; ein NULL-Snapshot (leere DB) erzeugt valide leere/0-Ausgabe statt der
Altcode-ERROR-Zeile bzw. des HA-error-state.

Die Charakterisierer des KAPUTTEN v1 (tests/characterization/test_metrics_export_
contract.py) laufen davon getrennt gegen ``modules.metrics`` -- diese Tests hier
binden den v2-Pfad gegen die geheilte Form (analog der M.7-_SLA_STAT-Naht).
"""

from domain.metrics import (
    MetricsSnapshot,
    RttPoint,
    SlaPoint,
    to_homeassistant,
    to_influxdb,
    to_prometheus,
)

# Ein voller Snapshot mit allen Quellen befuellt -- inkl. rtt_points (alive),
# die der M.4-Fix erst sichtbar macht.
_FULL = MetricsSnapshot(
    device_total=2,
    device_known=1,
    device_unknown=1,
    device_active_1h=1,
    device_active_24h=2,
    rtt_points=(
        RttPoint(target_id="wlan", rtt_ms=5.0, alive=True),
        RttPoint(target_id="gw", rtt_ms=-1.0, alive=False),
    ),
    sla_points=(
        SlaPoint(target_id="wlan", uptime_pct=99.5, avg_rtt_ms=4.2),
        SlaPoint(target_id="gw", uptime_pct=50.0, avg_rtt_ms=None),
    ),
    scans_7d=7,
    scan_hosts_max=42,
    alerts_24h=3,
)


# ── Prometheus ─────────────────────────────────────────────────────────────


def test_prometheus_device_gauges() -> None:
    out = to_prometheus(_FULL, now_ms=1_700_000_000_000)
    assert "# HELP cernis_devices_total Total devices in database" in out
    assert "# TYPE cernis_devices_total gauge" in out
    assert "cernis_devices_total 2" in out
    assert "cernis_devices_known 1" in out
    assert "cernis_devices_unknown 1" in out
    assert "cernis_devices_active_1h 1" in out
    assert "cernis_devices_active_24h 2" in out


def test_prometheus_monitor_block_present_when_alive_data() -> None:
    # GEHEILT: der in v1 stille Monitor-Block erscheint jetzt (rtt_history.alive).
    out = to_prometheus(_FULL, now_ms=0)
    assert 'cernis_monitor_rtt_ms{target="wlan"} 5.0' in out
    assert 'cernis_monitor_up{target="wlan"} 1' in out
    # Nicht-erreichbares Target: rtt_ms<=0 -> 0 (Altcode-Klammer), up=0.
    assert 'cernis_monitor_rtt_ms{target="gw"} 0' in out
    assert 'cernis_monitor_up{target="gw"} 0' in out


def test_prometheus_sla_block_and_avg_rtt_conditional() -> None:
    out = to_prometheus(_FULL, now_ms=0)
    assert 'cernis_sla_uptime_pct{target="wlan"} 99.5' in out
    assert 'cernis_sla_avg_rtt_ms{target="wlan"} 4.2' in out
    assert 'cernis_sla_uptime_pct{target="gw"} 50.0' in out
    # avg_rtt_ms=None -> die avg-Zeile fuer gw fehlt (Altcode ``if row["avg_rtt"]``).
    assert 'cernis_sla_avg_rtt_ms{target="gw"}' not in out


def test_prometheus_scan_block() -> None:
    out = to_prometheus(_FULL, now_ms=0)
    assert "# TYPE cernis_scans_last_7d counter" in out
    assert "cernis_scans_last_7d 7" in out
    assert "cernis_scan_hosts_max 42" in out


def test_prometheus_alerts_24h_present_with_altcode_wording() -> None:
    # A.7b: cernis_alerts_24h NUR in Prometheus, exakt Altcode-Wortlaut (counter).
    out = to_prometheus(_FULL, now_ms=0)
    assert "# HELP cernis_alerts_24h Alerts fired in last 24h" in out
    assert "# TYPE cernis_alerts_24h counter" in out
    assert "cernis_alerts_24h 3" in out


def test_prometheus_empty_snapshot_is_valid_zeroed_output() -> None:
    # GEHEILT (M.8-Robustheit): leere DB -> Null-Snapshot -> valide 0-Ausgabe,
    # NICHT die Altcode-ERROR-Zeile.
    out = to_prometheus(MetricsSnapshot(), now_ms=0)
    assert "# ERROR" not in out
    assert "cernis_devices_total 0" in out
    assert "cernis_scans_last_7d 0" in out
    # alerts_24h auch im Null-Snapshot als 0 sichtbar (A.7b, leere-History).
    assert "cernis_alerts_24h 0" in out
    # keine Target-abhaengigen Zeilen ohne rtt/sla-Punkte
    assert "cernis_monitor_rtt_ms{" not in out
    assert "cernis_sla_uptime_pct{" not in out
    # endet mit Leerzeile (Altcode-treu)
    assert out.endswith("\n")


# ── InfluxDB ───────────────────────────────────────────────────────────────


def test_influxdb_device_line_and_rtt_lines() -> None:
    out = to_influxdb(_FULL, measurement="cernis", now_ns=1234567890)
    lines = out.split("\n")
    assert "cernis,source=devices total=2i,known=1i,active_24h=2i 1234567890" in lines
    # GEHEILT: rtt-Zeilen pro Target (v1: dauerhaft "").
    assert "cernis,target=wlan rtt_ms=5.0,up=1i 1234567890" in lines
    assert "cernis,target=gw rtt_ms=-1.0,up=0i 1234567890" in lines


def test_influxdb_target_id_sanitized() -> None:
    snap = MetricsSnapshot(rtt_points=(RttPoint("a b,c", 3.0, True),))
    out = to_influxdb(snap, measurement="cernis", now_ns=1)
    # Leerzeichen -> "_", Komma entfernt (Altcode-treu).
    assert "cernis,target=a_bc rtt_ms=3.0,up=1i 1" in out


def test_influxdb_empty_snapshot_emits_zeroed_device_line() -> None:
    # GEHEILT: leere DB -> valide 0-Device-Zeile (v1: "").
    out = to_influxdb(MetricsSnapshot(), measurement="cernis", now_ns=99)
    assert out == "cernis,source=devices total=0i,known=0i,active_24h=0i 99"


def test_influxdb_has_no_alerts_24h() -> None:
    # VERTRAG (A.7b): v1 fuehrte alerts_24h NUR in Prometheus; influx bewusst ohne --
    # charakterisierungstreu, keine Format-Erweiterung. Festgenagelt, damit niemand
    # spaeter denkt es sei vergessen UND eine versehentliche Erweiterung rot wird.
    out = to_influxdb(_FULL, measurement="cernis", now_ns=1)
    assert "alerts_24h" not in out
    assert "alerts" not in out


# ── Home Assistant ─────────────────────────────────────────────────────────


def test_homeassistant_real_state_dict() -> None:
    # GEHEILT: echter State-Dict (v1: dauerhaft error-state, weil alive fehlte).
    out = to_homeassistant(_FULL)
    assert out["state"] == 1
    assert out["attributes"]["devices_total"] == 2
    assert out["attributes"]["devices_online"] == 1
    assert out["attributes"]["unit_of_measurement"] == "devices"
    assert out["attributes"]["friendly_name"] == "CERNIS PRO Network"
    assert out["attributes"]["icon"] == "mdi:lan"
    assert out["attributes"]["monitor"] == {
        "wlan": {"alive": True, "rtt_ms": 5.0},
        "gw": {"alive": False, "rtt_ms": -1.0},
    }


def test_homeassistant_empty_snapshot_is_zero_state_not_error() -> None:
    # GEHEILT (M.8-Robustheit): leere DB -> 0-State, KEIN error-state.
    out = to_homeassistant(MetricsSnapshot())
    assert out["state"] == 0
    assert "error" not in out["attributes"]
    assert out["attributes"]["devices_total"] == 0
    assert out["attributes"]["monitor"] == {}


def test_homeassistant_has_no_alerts_24h() -> None:
    # VERTRAG (A.7b): v1 fuehrte alerts_24h NUR in Prometheus; HA bewusst ohne --
    # charakterisierungstreu, keine Format-Erweiterung (s. influx-Vertrag).
    out = to_homeassistant(_FULL)
    assert "alerts_24h" not in out["attributes"]
    assert "alerts" not in out["attributes"]
