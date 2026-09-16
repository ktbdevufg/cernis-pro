"""Application-Exceptions der traffic-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert in
``api/`` (T.3). Vorerst NUR die Basisklasse: ``ListAppTraffic`` ist ein reiner
Lese-Pass-Through (leere Verbindungssicht -> ``[]`` ist kein Fehler),
``CheckTrafficPermission`` gibt eine ``{ok, error}``-Naht zurueck (fehlendes Recht
ist KEINE Exception, sondern ein Ergebniswert), und ``MeasureThroughput`` ist reine
zustandsfreie Domaenen-Anwendung. Es gibt also noch keinen spezifischen Fehlerfall.

Die Basisklasse folgt dem Projektmuster (scanning/devices/interfaces fuehren je eine
``*ApplicationError``-Basis) und dient als gemeinsamer Aufhaenger, falls spaetere
traffic-Use-Cases (Polling-Zustand T.4) echte Fehler brauchen.
"""


class TrafficApplicationError(Exception):
    """Basis fuer Fehler der traffic-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
