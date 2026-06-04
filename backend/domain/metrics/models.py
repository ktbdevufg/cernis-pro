"""Datentraeger des metrics-Querschnitts -- reine Wertobjekte (stdlib, ADR 0002).

metrics ist ein LESE-/AGGREGAT-QUERSCHNITT ueber mehrere Quell-Domaenen (devices,
rtt_history, sla_samples, scan_history, alert_history (A.7b)). Es ist KEINE
Fach-Domaene mit Verhalten, sondern buendelt die fertig aggregierten Kennzahlen aus
diesen Quellen fuer den Export (Prometheus / InfluxDB / Home Assistant).

WICHTIG zur Domaenen-Reinheit (jede Domaene eigenstaendig): ``MetricsSnapshot`` und
die Punkt-Typen halten EIGENE schmale Felder/Primitive -- sie importieren KEINE
Modelle der Quell-Domaenen (kein ``domain/metrics`` -> ``domain/devices`` /
``domain/scanning`` / ``domain/monitoring``). Der import-linter erzwingt diese
Kante NICHT (die forbidden-Contracts decken nur die Ring-Grenzen, nicht domain-
interne Querverbindungen) -- es ist eine bewusste Schnitt-Disziplin: ein
metrics-Aggregat, das ``DeviceStats``/``PingSample``/``SlaSample``/``ScanSummary``
komponierte, verdrahtete vier Domaenen quer und braechte ihre Eigenstaendigkeit.

Darum die bewusst ABWEICHENDEN Felder gegenueber den Quell-Modellen:

* ``device_active_1h`` UND ``device_active_24h`` -- der Altcode-Prometheus-Block
  exponiert ZWEI Aktiv-Fenster; ``domain.devices.DeviceStats`` traegt nur EINES
  (``active``). Eigene Zwei-Fenster-Felder statt Reuse.
* ``RttPoint(target_id, rtt_ms, alive)`` -- nur die drei vom Export benoetigten
  Felder; ``domain.monitoring.PingSample`` traegt zusaetzlich host/loss/timestamp
  (Loop-Kontext), den metrics nicht braucht.
* ``SlaPoint(target_id, uptime_pct, avg_rtt_ms)`` -- die FERTIG aggregierten
  24h-GROUP-BY-Kennzahlen des Altcode-SLA-Blocks, NICHT die rohen ``SlaSample``-
  Zeilen und NICHT die ``compute_sla_stats``-Rechnung (das ist die days/chart-
  Aggregation eines anderen Belangs, M.7).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RttPoint:
    """Letzter RTT-Messpunkt EINES Monitor-Targets (latest-per-target).

    ``rtt_ms`` ist der zuletzt gemessene RTT (Sentinel/0 fuer "keine RTT", wie der
    Adapter ihn aus ``rtt_history`` liest); ``alive`` der zugehoerige
    Erreichbarkeits-Zustand (die in M.4 ergaenzte ``rtt_history.alive``-Spalte --
    HIER wird der Fix sichtbar: dieser Punkt existierte im toten v1-Strang nie).
    """

    target_id: str
    rtt_ms: float
    alive: bool


@dataclass(frozen=True)
class SlaPoint:
    """Fertig aggregierte 24h-SLA-Kennzahlen EINES Targets (Altcode-GROUP-BY).

    ``uptime_pct`` = ``alive_count / total * 100`` ueber das 24h-Fenster (3 Dez,
    wie der Altcode-Prometheus-SLA-Block). ``avg_rtt_ms`` ist der Mittelwert der
    RTTs mit ``rtt_ms > 0`` (2 Dez) oder ``None``, wenn es keine solche RTT gab --
    der Altcode emittiert die ``cernis_sla_avg_rtt_ms``-Zeile nur dann (``if
    row["avg_rtt"]``), ``None`` traegt diese "weglassen"-Semantik in die reine
    Format-Funktion.
    """

    target_id: str
    uptime_pct: float
    avg_rtt_ms: float | None


@dataclass(frozen=True)
class MetricsSnapshot:
    """Ein vollstaendiger metrics-Lese-Querschnitt zu EINEM Zeitpunkt.

    Das Aggregat, das der ``MetricsReader`` fuellt und die reinen Format-Funktionen
    (``to_prometheus`` / ``to_influxdb`` / ``to_homeassistant``) in Export-Form
    bringen. Reine Felder/Primitive + die eigenen Punkt-Typen -- kein Quell-Domaenen-
    Import (s. Modul-Kommentar).

    leere-DB-Robustheit (M.8, bewusste v2-Verbesserung gegenueber dem kaputten v1):
    eine leere/fehlende Quell-Tabelle fuehrt im Adapter zu ``0`` bzw. ``[]`` --
    NICHT zu einem Throw und NICHT zur Altcode-ERROR-Zeile/zum HA-error-state. Der
    Null-Snapshot (alle Zaehler 0, alle Listen leer) ist damit ein valider Zustand,
    der valide leere/0-Metriken erzeugt.

    ``alerts_24h`` (A.7b): COUNT der ``alert_history``-Zeilen der letzten 24h. In M.8
    bewusst ausgelassen (alerting war nicht migriert -> Vorwaerts-Kopplung an eine
    nicht-existente Domaene); ab A.7a beschreibt der monitor-Trigger ``alert_history``
    real, darum jetzt freigeschaltet. Es ist ein NACKTER ``int`` -- KEIN Import aus
    ``domain.alerting`` (die metrics-Domaene bleibt isoliert; der Reader liest die
    ``alert_history``-Tabelle DIREKT per SQL, wie rtt_history/sla_samples, nicht ueber
    den alerting-Port). Charakterisierungstreu wird das Feld NUR von ``to_prometheus``
    gerendert -- der Altcode fuehrte ``cernis_alerts_24h`` ausschliesslich im
    Prometheus-Block; influx/HA hatten es nie (s. ``format.py``). Welche Formate ein
    Snapshot-Feld rendern, ist Sache der Format-Funktionen -- das Feld selbst ist
    formatuebergreifend nur Datum.
    """

    # ── devices (ISO-Text-Zeitachse: last_seen) ──────────────────────────────
    device_total: int = 0
    device_known: int = 0
    device_unknown: int = 0
    device_active_1h: int = 0
    device_active_24h: int = 0

    # ── rtt_history (epoch-float-Zeitachse: ts) -- latest pro Target ──────────
    rtt_points: tuple[RttPoint, ...] = ()

    # ── sla_samples (epoch-float-Zeitachse: ts) -- 24h-Aggregat pro Target ────
    sla_points: tuple[SlaPoint, ...] = ()

    # ── scan_history (ISO-Text-Zeitachse: scanned_at) -- 7d-Aggregat ──────────
    scans_7d: int = 0
    scan_hosts_max: int = 0

    # ── alert_history (epoch-float-Zeitachse: ts) -- 24h-COUNT (A.7b) ─────────
    alerts_24h: int = 0
