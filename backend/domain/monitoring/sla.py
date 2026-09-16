"""SLA-/Uptime-Rechenlogik der monitoring-Domaene -- reine Funktionen (stdlib).

Verhaltensgleich aus dem Altcode portiert (``modules/sla.py``: der reine
Rechen-Anteil von ``get_sla_stats`` Z.64-90 und ``_build_hourly_chart``
Z.93-120). Der DB-Zugriff (``sqlite3``-Query auf ``sla_samples``) bleibt
BEWUSST draussen -- er gehoert in den M.7-Adapter. Diese Funktionen nehmen die
bereits geladenen Sample-Zeilen als Eingabe und geben die Rechnung zurueck.

Eine Sample-Zeile ist ``(alive, rtt_ms, ts)`` -- genau die Spaltenreihenfolge der
Altcode-Query ``SELECT alive, rtt_ms, ts FROM sla_samples``. ``alive`` ist im
Altcode-Schema ein INTEGER (0/1), wird hier wie dort truthy ausgewertet.

BEFUND (parametrisiert in C-3): ``downtime_mins`` rechnet die Downtime-Minuten als
``down_count * interval_s / 60``. Historisch war das Intervall HARTCODIERT 5 Sekunden
(charakterisierungstreu aus dem Altcode, wo es separat als ``_interval`` lebte und
nicht zwingend 5 war). Der Logging-SLA-Pfad (C-3) hat aber pro Task ein waehlbares
``interval_s`` -- darum ist der Wert jetzt ein OPTIONALER Parameter ``interval_s: int
= 5``: der Default 5 haelt die bestehenden Aufrufer (``GetSlaStats``/``GetAllSlaStats``
ueber ``sla_samples``) VERHALTENSGLEICH, der Logging-SLA-Use-Case reicht das echte
``task.interval_s`` durch. Die ``uptime_pct`` ist intervall-UNABHAENGIG (reines
alive/total) -- nur die Downtime-Minuten-Schaetzung haengt am Intervall.

WEITERER BEFUND (treu uebernommen): die avg_rtt-Filter UNTERSCHEIDEN sich zwischen
Gesamt-Stat und Chart. In ``compute_sla_stats`` zaehlen nur RTTs lebendiger
Samples mit ``rtt > 0`` (``alive and rtt > 0``); im Chart-Bucket dagegen ALLE
Samples mit ``rtt > 0``, unabhaengig von ``alive`` (``rtt > 0``). Altcode-IST,
hier 1:1 erhalten.
"""

from datetime import datetime
from typing import Any

# Eine geladene Sample-Zeile: (alive, rtt_ms, ts) -- Spaltenreihenfolge der
# Altcode-Query. ``alive`` truthy (Schema-INTEGER 0/1), ``rtt_ms``/``ts`` float.
type SlaSample = tuple[float, float, float]


def compute_sla_stats(rows: list[SlaSample], days: int, interval_s: int = 5) -> dict[str, Any]:
    """Berechnet die SLA-Gesamtstatistik aus geladenen Sample-Zeilen.

    Reproduziert ``modules/sla.get_sla_stats`` ab dem DB-Read: leere ``rows`` ->
    Null-Stats mit ``uptime_pct=None`` (NICHT 0); sonst uptime% (3 Dez), downtime
    in Minuten (1 Dez), avg_rtt (2 Dez, default 0) und der Hourly-Chart.
    ``target_id`` ist hier KEIN Parameter -- die Domaene kennt das DB-Schluesselfeld
    nicht; der M.7-Adapter setzt es in das Ergebnis-dict, wenn noetig.

    ``interval_s`` (Default 5) steuert NUR die Downtime-Minuten-Schaetzung
    (``down_count * interval_s / 60``): der Default haelt die bestehenden
    ``sla_samples``-Aufrufer verhaltensgleich, der Logging-SLA-Pfad (C-3) reicht das
    Task-Intervall durch. Die ``uptime_pct`` bleibt davon UNBERUEHRT (reines
    alive/total).
    """
    if not rows:
        return {
            "days": days,
            "samples": 0,
            "uptime_pct": None,
            "downtime_mins": 0,
            "avg_rtt_ms": 0,
            "chart": [],
        }

    total = len(rows)
    alive_count = sum(1 for r in rows if r[0])
    rtts = [r[1] for r in rows if r[0] and r[1] > 0]
    avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else 0
    uptime_pct = round(alive_count / total * 100, 3)

    # Downtime-Schaetzung in Minuten -- parametrisiertes Intervall (BEFUND oben).
    down_count = total - alive_count
    downtime_mins = round(down_count * interval_s / 60, 1)

    chart = build_hourly_chart(rows, days)

    return {
        "days": days,
        "samples": total,
        "uptime_pct": uptime_pct,
        "downtime_mins": downtime_mins,
        "avg_rtt_ms": avg_rtt,
        "chart": chart,
    }


def build_hourly_chart(rows: list[SlaSample], days: int) -> list[dict[str, Any]]:
    """Aggregiert Sample-Zeilen in stuendliche Buckets fuer das Chart.

    Reproduziert ``modules/sla._build_hourly_chart``: Gruppierung per
    ``int(ts // 3600) * 3600``, je Bucket uptime% (1 Dez) und avg_rtt (1 Dez,
    default 0), ``datetime`` als ``"%d.%m %H:00"``. Gibt die letzten 168 Buckets
    (7 Tage) zurueck. ``days`` ist im Altcode hier ungenutzt -- nur fuer
    Signatur-Treue mitgefuehrt.
    """
    if not rows:
        return []

    buckets: dict[int, list[tuple[float, float]]] = {}
    for alive, rtt, ts in rows:
        hour_key = int(ts // 3600) * 3600
        buckets.setdefault(hour_key, []).append((alive, rtt))

    chart: list[dict[str, Any]] = []
    for hour_ts in sorted(buckets.keys()):
        samples = buckets[hour_ts]
        alive_n = sum(1 for a, _ in samples if a)
        # Chart-Filter: ALLE Samples mit rtt > 0 (KEIN alive-Filter -- s. BEFUND).
        rtts = [r for _, r in samples if r > 0]
        chart.append(
            {
                "ts": hour_ts,
                "datetime": datetime.fromtimestamp(hour_ts).strftime("%d.%m %H:00"),
                "uptime_pct": round(alive_n / len(samples) * 100, 1),
                "avg_rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else 0,
                "samples": len(samples),
            }
        )

    # Letzte 168 Stunden (7 Tage) fuer die Chart-Lesbarkeit (Altcode-Cap).
    return chart[-168:]
