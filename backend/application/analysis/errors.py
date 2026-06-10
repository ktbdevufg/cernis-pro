"""Application-Exceptions der analysis-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert in
``api/`` (spaeterer Schnitt). Vorerst NUR die Basisklasse: ``AnalyzeSnapshot`` ist ein
reiner Lese-/Rechen-Pass-Through (``evaluate`` ist rein, die Ports sind synchrone
Lookups; ein leeres Ergebnis -> ``[]`` ist kein Fehler). Es gibt also noch keinen
spezifischen Fehlerfall.

Die Basisklasse folgt dem Projektmuster (process/scanning/devices/interfaces/traffic
fuehren je eine ``*ApplicationError``-Basis) und dient als gemeinsamer Aufhaenger, falls
spaetere analysis-Use-Cases echte Fehler brauchen.
"""


class AnalysisApplicationError(Exception):
    """Basis fuer Fehler der analysis-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
