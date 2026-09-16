"""Application-Exceptions der Lizenzaufstellungs-Use-Cases.

Eigene Fehlerklassen OHNE HTTP-Details -- das Mapping auf Statuscodes passiert in
``api/`` (Muster wie ``application/interfaces/errors.py``). Der api-Ring darf
``infrastructure`` nicht importieren und kann die Adapter-Fehler daher nicht direkt
fangen; er faengt diese Application-Fehler, in die der Use-Case uebersetzt.

Zwei Faelle, bewusst GETRENNT -- sie verdienen unterschiedliche HTTP-Antworten:

* ``LicenseTextUnknown`` -- der angefragte Schluessel existiert nicht (404): eine
  Anfrage nach etwas, das es nicht gibt.
* ``LicenseManifestUnavailable`` -- die Aufstellung selbst fehlt oder ist unlesbar
  (503): nicht die Anfrage ist falsch, sondern die Auslieferung ist unvollstaendig.

In BEIDEN Faellen ist der Fehler laut, nie eine leere Antwort mit 200 (Finding S3).
"""


class LicenseManifestApplicationError(Exception):
    """Basis fuer Fehler der Lizenzaufstellungs-Use-Cases (Aufhaenger fuer api/)."""


class LicenseManifestUnavailable(LicenseManifestApplicationError):
    """Die Aufstellung ist nicht auffindbar oder nicht lesbar.

    Traegt die Meldung des Adapters weiter -- bei einem Nichtfund also die
    vollstaendige Liste der geprueften Pfade, damit im Betrieb nachvollziehbar
    bleibt, wo gesucht wurde.
    """


class LicenseTextUnknown(LicenseManifestApplicationError):
    """Der angefragte Lizenztext-Schluessel steht nicht in der Aufstellung."""
