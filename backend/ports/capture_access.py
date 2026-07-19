"""Port der Capture-Rechteeinrichtung: Status abfragen + Rechte einrichten.

Vertrag fuer die plattformabhaengige Einrichtung des rohen Mitschnitt-Zugriffs
(macOS: Zugriff auf die BPF-Geraete ``/dev/bpf*`` ueber eine eigene Gruppe). Der
Port beschreibt NUR die zwei fachlichen Operationen; wie die Einrichtung technisch
laeuft (osascript, LaunchDaemon, Skript), weiss allein der Adapter.

Bewusst getrennt von ``ports.capture``/``ports.sni``: jene Ports LESEN Rechte
(``check_permission``), dieser VERAENDERT sie. Ein Adapter, der Rechte einrichtet,
ist ein anderer Belang als einer, der Pakete liefert (Muster der eigenstaendigen
Rechte-Ports ``ports.traffic.TrafficPermissionPort``/``ports.process``).

Rueckgaben sind Domaenenwerte (``CaptureAccessStatus``/``CaptureAccessResult``),
KEINE Wire-Form und kein ``dict``-Wildwuchs -- die Uebersetzung nach JSON macht der
api-Rand. KEIN stiller Fallback (S3): Erfolg, Abbruch durch den Nutzer und
Fehlschlag sind drei unterscheidbare Ergebnisse; ein Abbruch ist ein eigener
Zustand, kein Fehler.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/capture/interfaces/traffic/process). Die Vertragspruefung laeuft statisch
ueber mypy und ueber die Verdrahtung im Composition Root (``app.py``), nicht zur
Laufzeit per ``isinstance``.

``ports/`` kennt NUR ``domain``-Typen + stdlib/typing. KEIN ``infrastructure/``-
Import -- import-linter-Contract "ports kennen hoechstens domain".
"""

from typing import Protocol

from domain.capture_access import CaptureAccessResult, CaptureAccessStatus


class CaptureAccessPort(Protocol):
    """Vertrag der Rechteeinrichtung fuer den rohen Mitschnitt (Sniff-Familie)."""

    def status(self) -> CaptureAccessStatus:
        """Fragt ab, ob der rohe Mitschnitt-Zugriff eingerichtet ist.

        Schnelle, lokale Pruefung ohne Systemabfrage und ohne Passwortdialog --
        daher synchron (Muster ``ports.traffic.TrafficPermissionPort``). Der Aufruf
        veraendert NICHTS; er stellt nur fest, was da ist. Auf Plattformen ohne
        diese Einrichtung ist die ehrliche Antwort ``NOT_APPLICABLE``, kein Fehler.
        """
        ...

    def grant(self) -> CaptureAccessResult:
        """Richtet den Zugriff ein; liefert Erfolg, Abbruch oder Fehlschlag.

        Loest auf macOS die native Systemabfrage nach Administratorrechten aus
        (Touch ID moeglich). Der Aufruf BLOCKIERT, solange der Dialog offen ist --
        der Aufrufer (Use-Case) kapselt das ueber ``run_in_executor``, damit der
        Eventloop frei bleibt.

        Drei unterscheidbare Ausgaenge (S3): ``GRANTED`` (eingerichtet),
        ``CANCELLED`` (der Nutzer hat die Systemabfrage abgebrochen -- KEIN Fehler,
        jederzeit nachholbar) und ``FAILED`` mit benanntem Grund. Auf Plattformen
        ohne diese Einrichtung ``NOT_APPLICABLE``.
        """
        ...
