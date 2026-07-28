"""Linux-Adapter fuer ``TrafficPermissionPort`` (T.3, Rechte-/Sicht-Erkennung).

Erfuellt den ``TrafficPermissionPort`` strukturell: schnelle, synchrone, LOKALE
Pruefung der Sicht-Tiefe -- kein Netz-/Loop-I/O (Muster ``infrastructure/capture``
``check_permission``).

MESSBEFUND (L3, Findings 5/6): Der Durchsatz je Programm braucht auf Linux KEINE
erhoehten Rechte. ``ss -tin`` liefert die kumulativen TCP-Byte-Zaehler
(``bytes_sent``/``bytes_received``) als gewoehnlicher Benutzer vollstaendig -- auf
zwei Distributionen unabhaengig geprueft (Ubuntu: als Benutzer und als
Systemverwalter byte-identische Ausgabe; Fedora: je dieselbe Verbindungszahl).
Die frueher hier verankerte Annahme "Stufe 2 nur mit Root/CAP_NET_ADMIN" war
schlicht falsch und hat die Messung nie blockiert, sondern nur einen irrefuehrenden
Hinweis erzeugt. Darum entfaellt die Capability-/euid-Pruefung ersatzlos: Es gibt
nichts zu pruefen, wenn das Recht nicht gebraucht wird.

WAS STATTDESSEN GEPRUEFT WIRD: die einzige Bedingung, die den Durchsatz auf Linux
wirklich verhindern kann -- ob das Werkzeug ``ss`` (iproute2) ueberhaupt vorhanden
ist. Fehlt es, ist das ein echter, benennbarer Fehler (``NEEDS_PRIVILEGES`` als
"nicht nutzbar, mit Grund") und KEINE stille Null (S3). Der Rechte-Begriff im
Zustandsnamen bleibt aus Kompatibilitaet zur Wire-Form erhalten; die Bedeutung ist
"die Quelle steht nicht zur Verfuegung, hier ist der Grund".

Der Adapter verschafft sich selbst NIE Rechte und fordert auch keine an: Karls
Entscheidung (S57) ist, dass es keine Rechteerweiterung, keinen Terminal-Befehl im
Text und keinen Zustimmungsdialog gibt.

SCOPE (CLAUDE.md "Nur Linux x64"): ``is_available`` ist auf Nicht-Linux ``False``
(``/proc``/``sock_diag`` fehlen) -- der Use-Case sperrt dann den ganzen Feature-
Bereich, statt eine Halb-Implementierung vorzutaeuschen.
"""

import shutil
import sys

from domain.traffic import (
    TrafficPermissionCause,
    TrafficPermissionResult,
    TrafficPermissionState,
)

# Das Werkzeug, aus dem der Durchsatz stammt (siehe ``traffic_linux._run``). EINE
# Quelle fuer den Namen, damit Pruefung und Messung nicht auseinanderlaufen koennen.
_SS_BINARY = "ss"

# Grund, wenn das Werkzeug fehlt: sachlich, ohne Rechte-Rat (er wuerde hier nichts
# bewirken -- fehlendes iproute2 ist kein Rechteproblem). Die Oberflaeche zeigt
# ihren eigenen, uebersetzten Text; dieser Grund ist die technische Begruendung
# fuer Protokoll und API-Aufrufer.
_SS_MISSING_MESSAGE = (
    "Der Durchsatz je Programm braucht das Werkzeug 'ss' (Paket iproute2); "
    "es ist auf diesem System nicht auffindbar. Die Verbindungsliste bleibt "
    "davon unberuehrt."
)


def _ss_vorhanden() -> bool:
    """``True``, wenn ``ss`` im ``PATH`` auffindbar ist (I/O: nur PATH-Lookup).

    ``shutil.which`` ist der billige, seiteneffektfreie Weg -- kein Prozessstart.
    Damit ist die Pruefung so schnell wie die frueheren ``/proc``-Leseoperationen
    und erfuellt weiterhin den synchronen Port-Vertrag (kein Netz-/Loop-I/O).
    """
    return shutil.which(_SS_BINARY) is not None


class TrafficPermissionAdapter:
    """Erfuellt das ``TrafficPermissionPort``-Protocol (lokale Quellen-Pruefung, Linux)."""

    def is_available(self) -> bool:
        """``True`` auf Linux (psutil/``/proc`` da), sonst ``False``.

        Stufe 1 (psutil) ist plattformneutral, aber die Stufe-2-Quelle (``sock_diag``
        ueber ``ss``) ist Linux -- auf Nicht-Linux wird der ganze Feature-Bereich
        ehrlich als nicht verfuegbar gemeldet, statt eine Halb-Implementierung
        vorzutaeuschen (CLAUDE.md "Nur Linux x64").
        """
        return sys.platform.startswith("linux")

    def check_permission(self) -> str | None:
        """``None``, wenn der Durchsatz messbar ist, sonst der Grund (fehlendes ``ss``).

        Auf Linux ist der Durchsatz rootless messbar (Messbefund oben) -- die
        einzige Bedingung ist das vorhandene Werkzeug. Ist es da, gibt es nichts zu
        melden (``None``); fehlt es, wird das benannt statt verschwiegen (S3).
        """
        if _ss_vorhanden():
            return None
        return _SS_MISSING_MESSAGE

    def permission_state(self) -> TrafficPermissionResult:
        """``GRANTED``, wenn der Durchsatz messbar ist, sonst ``NEEDS_PRIVILEGES``+Grund.

        Auf Linux ist die Messung ohne erhoehte Rechte moeglich, darum ist ``GRANTED``
        der Normalfall -- der Zustand beschreibt die Sicht auf den Durchsatz, und die
        steht. Fehlt das Werkzeug, ist die Quelle nicht nutzbar: das bleibt ein
        sichtbarer Fehlzustand mit Grund, nie eine stille Null. ``NOT_APPLICABLE``
        gehoert weiterhin ausschliesslich Plattformen, die die Messung gar nicht
        anbieten (siehe ``traffic_macos``) -- dieser Adapter vergibt ihn nie.
        Der Text bleibt derselbe wie in ``check_permission`` -- eine Quelle, zwei
        Sichten auf denselben Befund.

        Der Fehlzustand traegt zusaetzlich die URSACHE ``TOOL_MISSING`` als Merkmal:
        derselbe Befund, den ``reason`` als Freitext erklaert, noch einmal maschinell
        auswertbar -- die Oberflaeche soll ihn nicht aus dem Text lesen muessen. Der
        Zustand und der Grundtext bleiben davon unberuehrt (kein Bruch).
        """
        text = self.check_permission()
        if text is None:
            return TrafficPermissionResult(state=TrafficPermissionState.GRANTED)
        return TrafficPermissionResult(
            state=TrafficPermissionState.NEEDS_PRIVILEGES,
            reason=text,
            cause=TrafficPermissionCause.TOOL_MISSING,
        )
