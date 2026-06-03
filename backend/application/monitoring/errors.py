"""Application-Exceptions der monitoring-Use-Cases.

Eigene Fehlerklassen OHNE HTTP-/Transport-Details -- das Mapping auf WS-Frames bzw.
Statuscodes passiert in ``api/`` (M.9).

Der ``RunMonitor``-Loop ist best-effort und propagiert im Normalbetrieb keine
Fehler an den Aufrufer (Notifier-Fehler faengt der Adapter mit Log; Ping liefert
einen ``alive=False``-``PingSample`` statt zu werfen). Diese Basisklasse ist der
gemeinsame Aufhaenger fuer kuenftige monitoring-Use-Case-Fehler (z. B. Lese-Pfade
in M.7/M.9), analog ``ScanningApplicationError``.
"""


class MonitoringApplicationError(Exception):
    """Basis fuer Fehler der monitoring-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
