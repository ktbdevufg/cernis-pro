"""
CERNIS PRO Metrics Export
Provides Prometheus-compatible metrics endpoint and InfluxDB line protocol export.
Allows integration with Grafana, Prometheus, InfluxDB, Home Assistant etc.
"""
import time
import sqlite3
import json
from pathlib import Path

from modules.db_path import DB_PATH  # noqa


def _conn():
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    return c


# ── Prometheus metrics ────────────────────────────────────────

def generate_prometheus_metrics() -> str:
    """
    Generate Prometheus-compatible metrics in text exposition format.
    Expose at GET /metrics for scraping by Prometheus/Grafana.
    """
    lines = []
    now_ms = int(time.time() * 1000)

    def metric(name, help_text, type_str, samples):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {type_str}")
        for labels, value in samples:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            if label_str:
                lines.append(f'{name}{{{label_str}}} {value}')
            else:
                lines.append(f'{name} {value}')

    try:
        conn = _conn()

        # ── Device metrics ────────────────────────────────────
        stats_row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN is_known=1 THEN 1 ELSE 0 END) as known,
                SUM(CASE WHEN is_known=0 THEN 1 ELSE 0 END) as unknown,
                SUM(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 ELSE 0 END) as active_1h,
                SUM(CASE WHEN last_seen > datetime('now', '-1 day') THEN 1 ELSE 0 END) as active_24h
            FROM devices
        """).fetchone()

        if stats_row:
            metric("pulsar_devices_total", "Total devices in database", "gauge",
                   [{}, stats_row["total"] or 0])
            metric("pulsar_devices_known", "Known devices", "gauge",
                   [{}, stats_row["known"] or 0])
            metric("pulsar_devices_unknown", "Unknown/new devices", "gauge",
                   [{}, stats_row["unknown"] or 0])
            metric("pulsar_devices_active_1h", "Devices active in last hour", "gauge",
                   [{}, stats_row["active_1h"] or 0])
            metric("pulsar_devices_active_24h", "Devices active in last 24h", "gauge",
                   [{}, stats_row["active_24h"] or 0])

        # ── Monitor/SLA metrics ───────────────────────────────
        try:
            rtt_rows = conn.execute("""
                SELECT target_id, rtt_ms, alive, ts
                FROM rtt_history
                WHERE ts > ?
                ORDER BY target_id, ts DESC
            """, (time.time() - 300,)).fetchall()  # last 5 min

            seen_targets = set()
            for row in rtt_rows:
                tid = row["target_id"]
                if tid in seen_targets:
                    continue
                seen_targets.add(tid)
                metric("pulsar_monitor_rtt_ms", "Latest RTT in milliseconds", "gauge",
                       [{"target": tid}, row["rtt_ms"] if row["rtt_ms"] > 0 else 0])
                metric("pulsar_monitor_up", "Monitor target up (1) or down (0)", "gauge",
                       [{"target": tid}, row["alive"]])
        except Exception:
            pass

        # ── SLA metrics ───────────────────────────────────────
        try:
            cutoff_24h = time.time() - 86400
            sla_rows = conn.execute("""
                SELECT target_id,
                    COUNT(*) as total,
                    SUM(alive) as alive_count,
                    AVG(CASE WHEN rtt_ms > 0 THEN rtt_ms END) as avg_rtt
                FROM sla_samples
                WHERE ts > ?
                GROUP BY target_id
            """, (cutoff_24h,)).fetchall()

            for row in sla_rows:
                uptime = round((row["alive_count"] / row["total"]) * 100, 3) if row["total"] else 0
                metric("pulsar_sla_uptime_pct", "Uptime percentage last 24h", "gauge",
                       [{"target": row["target_id"]}, uptime])
                if row["avg_rtt"]:
                    metric("pulsar_sla_avg_rtt_ms", "Average RTT last 24h", "gauge",
                           [{"target": row["target_id"]}, round(row["avg_rtt"], 2)])
        except Exception:
            pass

        # ── Scan metrics ──────────────────────────────────────
        try:
            scan_row = conn.execute("""
                SELECT COUNT(*) as total,
                    MAX(host_count) as max_hosts,
                    AVG(host_count) as avg_hosts
                FROM scan_history
                WHERE scanned_at > datetime('now', '-7 days')
            """).fetchone()
            if scan_row:
                metric("pulsar_scans_last_7d", "Number of scans in last 7 days", "counter",
                       [{}, scan_row["total"] or 0])
                metric("pulsar_scan_hosts_max", "Maximum hosts found in a scan (7d)", "gauge",
                       [{}, scan_row["max_hosts"] or 0])
        except Exception:
            pass

        # ── Alert metrics ─────────────────────────────────────
        try:
            alert_row = conn.execute("""
                SELECT COUNT(*) as total FROM alert_history
                WHERE ts > ?
            """, (time.time() - 86400,)).fetchone()
            metric("pulsar_alerts_24h", "Alerts fired in last 24h", "counter",
                   [{}, alert_row["total"] or 0])
        except Exception:
            pass

        conn.close()

    except Exception as e:
        lines.append(f"# ERROR generating metrics: {e}")

    lines.append("")  # trailing newline
    return "\n".join(lines)


# ── InfluxDB Line Protocol ────────────────────────────────────

def generate_influxdb_lines(measurement: str = "pulsar") -> str:
    """
    Generate InfluxDB line protocol for write API.
    POST to http://influxdb:8086/write?db=pulsar
    """
    lines = []
    now_ns = int(time.time() * 1e9)

    try:
        conn = _conn()

        # Device stats
        stats = conn.execute("""
            SELECT COUNT(*) as total,
                SUM(CASE WHEN is_known=1 THEN 1 ELSE 0 END) as known,
                SUM(CASE WHEN last_seen > datetime('now', '-1 day') THEN 1 ELSE 0 END) as active
            FROM devices
        """).fetchone()
        if stats:
            lines.append(
                f"{measurement},source=devices "
                f"total={stats['total'] or 0}i,"
                f"known={stats['known'] or 0}i,"
                f"active_24h={stats['active'] or 0}i "
                f"{now_ns}"
            )

        # RTT per target
        try:
            rows = conn.execute("""
                SELECT target_id, rtt_ms, alive FROM rtt_history
                WHERE ts > ? GROUP BY target_id HAVING MAX(ts)
            """, (time.time() - 60,)).fetchall()
            for r in rows:
                tid = r["target_id"].replace(" ", "_").replace(",", "")
                lines.append(
                    f"{measurement},target={tid} "
                    f"rtt_ms={r['rtt_ms'] or 0},"
                    f"up={r['alive'] or 0}i "
                    f"{now_ns}"
                )
        except Exception:
            pass

        conn.close()
    except Exception:
        pass

    return "\n".join(lines)


# ── Home Assistant REST sensor format ────────────────────────

def generate_homeassistant_state() -> dict:
    """
    JSON state for Home Assistant REST sensor integration.
    GET /api/export/homeassistant
    """
    try:
        conn = _conn()
        stats = conn.execute("""
            SELECT
                COUNT(*) as devices_total,
                SUM(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 ELSE 0 END) as online
            FROM devices
        """).fetchone()

        # Latest monitor status
        monitor_rows = conn.execute("""
            SELECT target_id, alive, rtt_ms FROM rtt_history
            WHERE ts > ? GROUP BY target_id HAVING MAX(ts)
        """, (time.time() - 120,)).fetchall()

        monitor = {r["target_id"]: {"alive": bool(r["alive"]), "rtt_ms": r["rtt_ms"]}
                   for r in monitor_rows}

        conn.close()

        return {
            "state": stats["online"] or 0,
            "attributes": {
                "devices_total": stats["devices_total"] or 0,
                "devices_online": stats["online"] or 0,
                "monitor": monitor,
                "unit_of_measurement": "devices",
                "friendly_name": "CERNIS PRO Network",
                "icon": "mdi:lan",
            }
        }
    except Exception as e:
        return {"state": "error", "attributes": {"error": str(e)}}
