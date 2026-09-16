"""Use-Case des metrics-Querschnitts: ``ExportMetrics`` (M.8).

Eigenes Paket ``application/metrics`` -- konsistent zum durchgaengigen metrics-
Querschnitt-Schnitt ueber alle vier Ringe (``domain/metrics``, ``ports/metrics``,
``infrastructure/metrics``, ``application/metrics``). NICHT in ``application/
monitoring`` gelegt: metrics ist kein monitoring-Belang, und der Use-Case importiert
nur ``ports.metrics`` + ``domain.metrics`` -- nichts monitoring-Spezifisches. (Im
domain-Ring erzwingt der independence-Contract diesen Schnitt; im application-Ring
gilt die Konsistenz ohne Contract.)

ExportMetrics ist Pass-Through-NAH: die GANZE Form-Logik sitzt in den reinen
``domain.metrics``-Format-Funktionen (uhrfrei, DB-frei). Der Use-Case orchestriert
nur ``reader.snapshot() -> to_*(...)`` und besorgt die EINE Seiteneffekt-Zutat, die
die reine Funktion nicht haben darf: den Timestamp (die Uhr). Der Reader liest die
Quell-Tabellen (Seiteneffekt hinterm Port), die Format-Funktion bleibt rein.

Kennt ``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` (import-linter:
"application kennt nicht infrastructure/api"). Der ``MetricsReader`` kommt als
Protocol-Typ per Constructor-Injection herein; die Verdrahtung an
``SqliteMetricsReader`` macht der Composition Root (``app.py``/main.py, M.8 Schritt 2).
"""

import time
from typing import Any

from domain.metrics import to_homeassistant, to_influxdb, to_prometheus
from ports.metrics import MetricsReader


class ExportMetrics:
    """Erzeugt die drei Export-Formate aus EINEM frischen ``MetricsSnapshot``.

    Drei Methoden, je ein Format -- jede liest einen frischen Snapshot (der Reader
    aggregiert pro Aufruf neu, wie der Altcode pro Request). Der Timestamp wird HIER
    aus der Uhr geholt und in die uhrfreie Format-Funktion gereicht; so bleibt die
    Domaenen-Funktion deterministisch testbar und der Use-Case haelt den einzigen
    Uhr-Zugriff.
    """

    def __init__(self, reader: MetricsReader) -> None:
        self._reader = reader

    def prometheus(self) -> str:
        """Prometheus-Text-Expositionsformat (``GET /metrics``)."""
        now_ms = int(time.time() * 1000)
        return to_prometheus(self._reader.snapshot(), now_ms=now_ms)

    def influxdb(self, measurement: str = "cernis") -> str:
        """InfluxDB-Line-Protocol (``GET /api/export/influxdb``)."""
        now_ns = int(time.time() * 1e9)
        return to_influxdb(self._reader.snapshot(), measurement=measurement, now_ns=now_ns)

    def homeassistant(self) -> dict[str, Any]:
        """Home-Assistant-REST-Sensor-State-Dict (``GET /api/export/homeassistant``)."""
        return to_homeassistant(self._reader.snapshot())
