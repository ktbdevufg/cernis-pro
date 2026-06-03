"""FastAPI-Router des metrics-Querschnitts (v2) -- die drei Export-Endpunkte.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich den Use-Case
``ExportMetrics`` aus ``application/`` (import-linter: api -> nur application).
Konkreter Adapter (``SqliteMetricsReader``), Port und ``domain``-Typen werden hier
NICHT importiert -- der Use-Case kommt per FastAPI-Dependency herein (Verdrahtung im
Composition Root ``app.py``). Muster 1:1 wie ``api/scanning.py`` / ``api/devices.py``
/ ``api/settings.py``.

Endpunkte (Form altcode-treu, jetzt ueber den v2-Pfad -> GEHEILTE Form, weil der
``MetricsReader`` ``rtt_history.alive`` liest, M.4):

* ``GET /metrics``                  -> Prometheus-Text (``text/plain; version=0.0.4``).
* ``GET /api/export/influxdb``       -> InfluxDB-Line-Protocol (``text/plain``).
* ``GET /api/export/homeassistant``  -> Home-Assistant-State-JSON.

WICHTIG zum Live-Zustand: Dieser Router lebt in der v2-App (``app.py:create_app``),
die NOCH NICHT der Live-Server ist -- ``main:app`` (Altcode-Monolith) bedient die
Endpunkte weiter ueber ``modules.metrics``, bis der Einstiegspunkt-Wechsel
(``main:app`` -> ``app:app``) bzw. M.9 erfolgt. Erst dann faellt ``modules/metrics.py``
weg (M.8-Nachzuegler). Hier wird die geheilte v2-Form in der v2-App per Endpunkt-Test
bewiesen.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from application.metrics import ExportMetrics

# /metrics liegt OHNE /api-Prefix (altcode-treu: Prometheus scrapet GET /metrics);
# die beiden /api/export/*-Endpunkte tragen den Pfad voll aus. Darum KEIN
# router-Prefix -- die drei Pfade werden je vollstaendig annotiert.
router = APIRouter(tags=["metrics"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem
# echten Use-Case verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_export_metrics() -> ExportMetrics:
    raise NotImplementedError("ExportMetrics wird in app.py verdrahtet")


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics(
    export_metrics: Annotated[ExportMetrics, Depends(provide_export_metrics)],
) -> PlainTextResponse:
    """Prometheus-kompatible Metriken (Text-Expositionsformat) fuer Scraping."""
    return PlainTextResponse(export_metrics.prometheus(), media_type="text/plain; version=0.0.4")


@router.get("/api/export/influxdb", response_class=PlainTextResponse)
def influxdb_export(
    export_metrics: Annotated[ExportMetrics, Depends(provide_export_metrics)],
) -> PlainTextResponse:
    """InfluxDB-Line-Protocol fuer die Write-API."""
    return PlainTextResponse(export_metrics.influxdb(), media_type="text/plain")


@router.get("/api/export/homeassistant")
def homeassistant_export(
    export_metrics: Annotated[ExportMetrics, Depends(provide_export_metrics)],
) -> dict[str, Any]:
    """JSON-State fuer die Home-Assistant-REST-Sensor-Integration."""
    return export_metrics.homeassistant()
