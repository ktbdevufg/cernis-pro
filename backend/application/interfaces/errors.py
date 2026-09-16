"""Application-Exceptions der interfaces-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert in
``api/`` (I.3). Vorerst NUR die Basisklasse: ``ListInterfaces`` ist ein reiner
Lese-Pass-Through (leere Discovery -> ``[]`` ist kein Fehler), es gibt also keinen
spezifischen Fehlerfall. Die Basisklasse folgt dem Projektmuster (devices/security
fuehren je eine ``*ApplicationError``-Basis) und dient als gemeinsamer Aufhaenger,
falls spaetere interfaces-Use-Cases echte Fehler brauchen.
"""


class InterfacesApplicationError(Exception):
    """Basis fuer Fehler der interfaces-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
