"""Use-Cases der Capture-Rechteeinrichtung: Status abfragen + Einrichtung anstossen.

Zwei duenne Use-Cases ueber dem ``CaptureAccessPort`` (Muster der schlanken
Rechte-Nahtstellen ``application.traffic.CheckTrafficPermission``): sie halten
KEINE eigene Logik ueber BPF, LaunchDaemon oder osascript -- das ist Adapter-Sache.
Ihre Aufgabe ist, den Port aufzurufen und das Domaenen-Ergebnis unveraendert
weiterzureichen.

``application/`` kennt ``domain/`` + ``ports/``, NICHT ``infrastructure/``
(import-linter-Contract). Der konkrete Adapter kommt per Konstruktor herein,
verdrahtet im Composition Root (``app.py``).

Rueckgabe sind die Domaenenwerte selbst (``CaptureAccessStatus``/
``CaptureAccessResult``), KEINE Wire-Form -- die Projektion nach JSON macht der
api-Rand. Damit bleiben die drei Ausgaenge (Erfolg / Abbruch / Fehlschlag)
unterscheidbar, statt in einem ``{ok: bool}`` zu verschwinden (S3).
"""

import asyncio

from domain.capture_access import CaptureAccessResult, CaptureAccessStatus
from ports.capture_access import CaptureAccessPort


class GetCaptureAccessStatus:
    """Fragt ab, ob der rohe Mitschnitt-Zugriff eingerichtet ist."""

    def __init__(self, access: CaptureAccessPort) -> None:
        self._access = access

    def __call__(self) -> CaptureAccessStatus:
        """Liefert den Status-Befund unveraendert vom Port.

        Synchron: die Pruefung ist eine schnelle, lokale Dateiprobe ohne Netz- oder
        Loop-I/O und ohne Systemdialog (Muster ``CheckTrafficPermission``).
        """
        return self._access.status()


class GrantCaptureAccess:
    """Stoesst die Rechteeinrichtung an (loest auf macOS die Systemabfrage aus)."""

    def __init__(self, access: CaptureAccessPort) -> None:
        self._access = access

    async def __call__(self) -> CaptureAccessResult:
        """Richtet den Zugriff ein; liefert Erfolg, Abbruch oder Fehlschlag.

        ``async`` -- anders als die Status-Abfrage BLOCKIERT dieser Aufruf, solange
        der native Passwortdialog offen ist (Sekunden bis Minuten). Der synchrone
        Port-Aufruf wandert darum ueber ``asyncio.to_thread`` in einen Thread, damit
        der Eventloop frei bleibt und die uebrige API waehrend des Dialogs antwortet.

        Das ``CaptureAccessResult`` wird unveraendert durchgereicht: der Abbruch
        durch den Nutzer bleibt ein eigener Zustand und wird NICHT zu einem Fehler
        umgedeutet (S3).
        """
        return await asyncio.to_thread(self._access.grant)
