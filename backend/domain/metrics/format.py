"""Reine Format-Funktionen des metrics-Querschnitts: ``MetricsSnapshot`` -> Export.

Drei reine ``snapshot -> str/dict``-Funktionen, OHNE DB und OHNE Uhr-Zugriff fuer
die Werte (der Timestamp kommt als Parameter herein, damit die Funktion testbar und
deterministisch bleibt). Die Zeilen-/Feld-Form ist 1:1 aus dem Altcode
``modules/metrics.py`` rekonstruiert -- nur die Datenquelle ist jetzt der bereits
aggregierte Snapshot statt Inline-SQL.

GEHEILTE FORM (M.8, bewusste v2-Verhaltensaenderung): Weil der ``MetricsReader``
``rtt_history.alive`` liest (M.4-Wurzel-Fix) und eine leere DB als ``0``/``[]``
liefert (M.8-Robustheit), werden die in v1 toten Straenge hier LEBENDIG:

* ``cernis_monitor_rtt_ms`` / ``cernis_monitor_up`` erscheinen jetzt (v1: still weg,
  weil ``alive`` fehlte).
* InfluxDB liefert RTT-Zeilen (v1: ``""``).
* Home Assistant liefert einen echten State-Dict (v1: dauerhaft ``error-state``).
* Eine leere DB liefert valide leere/0-Ausgabe statt der Altcode-ERROR-Zeile bzw.
  des HA-error-state.

Diese Funktionen kennen die Heilung nicht -- sie formen nur, was im Snapshot steht.
Der Snapshot (Reader + Robustheit) IST die Heilung.
"""

from typing import Any

from domain.metrics.models import MetricsSnapshot


def to_prometheus(snapshot: MetricsSnapshot, now_ms: int) -> str:
    """Prometheus-Text-Expositionsformat (HELP/TYPE/Sample) aus dem Snapshot.

    Reproduziert ``generate_prometheus_metrics`` zeilenweise, gespeist aus dem
    Snapshot. ``now_ms`` wird -- wie im Altcode -- berechnet, aber in der Ausgabe
    nicht verwendet (die Gauges tragen keinen expliziten Timestamp); als Parameter
    mitgefuehrt fuer Signatur-Treue und damit die Funktion uhrfrei bleibt.
    Schliesst mit einer Leerzeile (``"\\n".join`` + trailing ``""``), wie der Altcode.
    """
    lines: list[str] = []

    def metric(
        name: str,
        help_text: str,
        type_str: str,
        samples: list[tuple[dict[str, str], Any]],
    ) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {type_str}")
        for labels, value in samples:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            if label_str:
                lines.append(f"{name}{{{label_str}}} {value}")
            else:
                lines.append(f"{name} {value}")

    # ── Device-Metriken ──────────────────────────────────────────────────────
    metric(
        "cernis_devices_total", "Total devices in database", "gauge", [({}, snapshot.device_total)]
    )
    metric("cernis_devices_known", "Known devices", "gauge", [({}, snapshot.device_known)])
    metric(
        "cernis_devices_unknown", "Unknown/new devices", "gauge", [({}, snapshot.device_unknown)]
    )
    metric(
        "cernis_devices_active_1h",
        "Devices active in last hour",
        "gauge",
        [({}, snapshot.device_active_1h)],
    )
    metric(
        "cernis_devices_active_24h",
        "Devices active in last 24h",
        "gauge",
        [({}, snapshot.device_active_24h)],
    )

    # ── Monitor-Metriken (GEHEILT via rtt_history.alive, M.4) ─────────────────
    for point in snapshot.rtt_points:
        metric(
            "cernis_monitor_rtt_ms",
            "Latest RTT in milliseconds",
            "gauge",
            [({"target": point.target_id}, point.rtt_ms if point.rtt_ms > 0 else 0)],
        )
        metric(
            "cernis_monitor_up",
            "Monitor target up (1) or down (0)",
            "gauge",
            [({"target": point.target_id}, int(point.alive))],
        )

    # ── SLA-Metriken (24h-Aggregat pro Target) ────────────────────────────────
    for sla in snapshot.sla_points:
        metric(
            "cernis_sla_uptime_pct",
            "Uptime percentage last 24h",
            "gauge",
            [({"target": sla.target_id}, sla.uptime_pct)],
        )
        # avg_rtt-Zeile nur, wenn es eine RTT gab (Altcode: ``if row["avg_rtt"]``).
        if sla.avg_rtt_ms is not None:
            metric(
                "cernis_sla_avg_rtt_ms",
                "Average RTT last 24h",
                "gauge",
                [({"target": sla.target_id}, sla.avg_rtt_ms)],
            )

    # ── Scan-Metriken (7d-Aggregat) ───────────────────────────────────────────
    metric(
        "cernis_scans_last_7d",
        "Number of scans in last 7 days",
        "counter",
        [({}, snapshot.scans_7d)],
    )
    metric(
        "cernis_scan_hosts_max",
        "Maximum hosts found in a scan (7d)",
        "gauge",
        [({}, snapshot.scan_hosts_max)],
    )

    lines.append("")  # trailing newline (Altcode-treu)
    return "\n".join(lines)


def to_influxdb(snapshot: MetricsSnapshot, measurement: str, now_ns: int) -> str:
    """InfluxDB-Line-Protocol aus dem Snapshot.

    Reproduziert ``generate_influxdb_lines``: eine ``source=devices``-Zeile mit den
    Device-Zaehlern und je eine ``target=<id>``-Zeile pro RTT-Punkt. ``now_ns`` ist
    der gemeinsame Timestamp aller Zeilen (vom Aufrufer hereingereicht, uhrfrei).
    Der Altcode saeubert die Target-id fuer das Tag (Leerzeichen -> ``_``, Kommata
    entfernt) -- hier 1:1 erhalten. Leerer Snapshot -> nur die Device-Zeile mit
    Null-Zaehlern (v1 lieferte bei leerer DB ``""`` -- die geheilte v2-Form liefert
    valide 0-Werte).
    """
    lines: list[str] = []

    lines.append(
        f"{measurement},source=devices "
        f"total={snapshot.device_total}i,"
        f"known={snapshot.device_known}i,"
        f"active_24h={snapshot.device_active_24h}i "
        f"{now_ns}"
    )

    for point in snapshot.rtt_points:
        tid = point.target_id.replace(" ", "_").replace(",", "")
        lines.append(
            f"{measurement},target={tid} rtt_ms={point.rtt_ms},up={int(point.alive)}i {now_ns}"
        )

    return "\n".join(lines)


def to_homeassistant(snapshot: MetricsSnapshot) -> dict[str, Any]:
    """Home-Assistant-REST-Sensor-State-Dict aus dem Snapshot.

    Reproduziert den ERFOLGS-Pfad von ``generate_homeassistant_state`` (der im v1
    mit echtem Schema unerreichbar war -- er setzte ``rtt_history.alive`` voraus,
    das v1 nie anlegte; M.4 heilt das). ``state`` = Anzahl online (1h-Fenster), der
    ``monitor``-Block bildet je Target ``{"alive": bool, "rtt_ms": ...}`` aus den
    RTT-Punkten. Leerer Snapshot -> ``state=0`` + leerer ``monitor`` (v1 lieferte
    error-state -- die geheilte v2-Form liefert einen echten 0-State).
    """
    monitor = {
        point.target_id: {"alive": point.alive, "rtt_ms": point.rtt_ms}
        for point in snapshot.rtt_points
    }
    return {
        "state": snapshot.device_active_1h,
        "attributes": {
            "devices_total": snapshot.device_total,
            "devices_online": snapshot.device_active_1h,
            "monitor": monitor,
            "unit_of_measurement": "devices",
            "friendly_name": "CERNIS PRO Network",
            "icon": "mdi:lan",
        },
    }
