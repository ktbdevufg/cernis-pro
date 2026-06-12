"""Application-Exceptions der resolver-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert im
Composition Root (``app.py``), nicht hier (Muster ``AnalysisApplicationError``). Der
``ResolveEndpoint``-Use-Case ist ein reiner Orchestrierungs-Pass-Through: er holt die
Rohfakten der vier Quell-Ports und stellt sie zu ``RemoteEndpointFacts`` zusammen. Eine
fehlende/leere Quelle ist KEIN Fehler (jedes Feld traegt ehrlich ``None``); die echten
Infrastruktur-Ausfaelle (``dig`` fehlt, Geo/ASN-CSV fehlt) sind infra-eigene Exceptions
der Adapter, die der Composition Root global auf 503 abbildet -- der Use-Case faengt sie
NICHT. Es gibt also noch keinen spezifischen application-Fehlerfall.

Die Basisklasse folgt dem Projektmuster (analysis/process/scanning/devices fuehren je eine
``*ApplicationError``-Basis) und dient als gemeinsamer Aufhaenger, falls spaetere
resolver-Use-Cases echte Fehler brauchen.
"""


class ResolverApplicationError(Exception):
    """Basis fuer Fehler der resolver-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
