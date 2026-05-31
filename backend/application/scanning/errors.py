"""Application-Exceptions der scanning-Use-Cases.

Eigene Fehlerklassen OHNE HTTP-/Transport-Details -- das Mapping auf WS-Frames
bzw. Statuscodes passiert in ``api/`` (S.6).

Bewusst KEINE Aufnahme der Adapter-Exceptions (``NmapScanError`` /
``FritzAuthError`` aus ``infrastructure.scanning``): die propagieren durch den
Use-Case-Generator HINDURCH und werden erst in ``api/`` (S.6) in einen sauberen
``error``-Frame uebersetzt (Entscheidung S.5: Durchwerfen, kein Fangen). Der
Use-Case kennt nur Ports, nie Infrastruktur -- die Schichtung bleibt sauber.
"""


class ScanningApplicationError(Exception):
    """Basis fuer Fehler der scanning-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""
