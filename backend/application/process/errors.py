"""Application-Exceptions der process-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert in
``api/`` (spaeterer Schnitt). Vorerst NUR die Basisklasse: ``ListProcesses`` ist ein
reiner Lese-Pass-Through (leere Prozess-Sicht -> ``[]`` ist kein Fehler) und
``CheckProcessPermission`` gibt eine ``{ok, error}``-Naht zurueck (fehlendes Recht ist
KEINE Exception, sondern ein Ergebniswert). Es gibt also noch keinen spezifischen
Fehlerfall.

Die Basisklasse folgt dem Projektmuster (scanning/devices/interfaces/traffic fuehren je
eine ``*ApplicationError``-Basis) und dient als gemeinsamer Aufhaenger, falls spaetere
process-Use-Cases echte Fehler brauchen.
"""


class ProcessApplicationError(Exception):
    """Basis fuer Fehler der process-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
