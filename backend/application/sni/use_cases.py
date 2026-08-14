"""Use-Cases der sni-Domaene -- Lifecycle des passiven SNI-Sniffs + Lese-Sicht.

Drei duenne Use-Cases ueber dem EINEN ``SniSnifferPort`` (Constructor-Injection als
Protocol-Typ, NIE ein konkreter Adapter). Kennt ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). KEIN Framework-Import,
KEIN ``asyncio.Task``-Management -- das ``create_task``/Teardown treibt der
Composition Root (Muster ``RunCapture``/``RunMonitor``/``PollThroughput``).

RINGPUFFER-ENTSCHEIDUNG (Vorgabe gab die Wahl frei, hier begruendet): Der Ringpuffer
der erfassten SNIs liegt im ADAPTER, NICHT in ``RunSniCapture``. Begruendung: Die
rohen Hits UND die periodischen Socket-Snapshots werden aus den zwei Hintergrund-
Threads des Adapters beschrieben (scapy-``AsyncSniffer`` + psutil-Poller), und die
Zuordnung braucht BEIDE zusammen. Ein ``deque(maxlen=...)`` am thread-lokalen
Schreib-Ort (Adapter) ist der natuerliche Ringpuffer; ihn in den Use-Case zu heben
hiesse, der Use-Case muesste in die laufenden Adapter-Threads hineingreifen -- mehr
Naht, kein Gewinn. Damit haelt ``RunSniCapture`` KEINEN eigenen State ausser dem
Adapter (anders als ``RunCapture``, dessen ``run()``-Loop ueber einen async-STROM
iteriert und Stats/Ringpuffer selbst fortschreibt -- hier gibt es keinen Strom, der
Adapter aggregiert intern).
"""

from typing import Any

from domain.sni import ObservedSni
from ports.sni import SniSnifferPort


class RunSniCapture:
    """Lifecycle-Halter des passiven SNI-Sniffs (Singleton, Muster ``RunCapture``).

    Eine langlebige Instanz pro App. ``start``/``stop``/``is_running`` delegieren an
    den Adapter (der die Hintergrund-Threads + den Ringpuffer haelt). KEIN eigener
    State, KEIN ``asyncio.Task`` -- der Composition Root umschliesst ``start`` mit dem
    ``create_task``/``app.state``-Geruest (Muster traffic poll/start), damit der
    lifespan-Shutdown sauber stoppen kann.
    """

    def __init__(self, sniffer: SniSnifferPort) -> None:
        self._sniffer = sniffer

    def start(self, interface: str | None) -> None:
        """Startet den passiven Sniff (delegiert; idempotent gegen einen aktiven Lauf).

        Ein Start-/Permission-Fehler propagiert als ``SniError`` aus dem Adapter -- der
        Aufrufer (StartSni-Naht) prueft ``is_available``/``check_permission`` vorher
        (uebersetzt den Permission-Fall in eine 403, bevor gestartet wird).
        """
        self._sniffer.start(interface)

    def stop(self) -> None:
        """Stoppt den Sniff (delegiert; idempotent)."""
        self._sniffer.stop()

    def is_running(self) -> bool:
        """``True``, solange der Sniffer-Thread laeuft (delegiert an den Adapter)."""
        return self._sniffer.is_running()

    def observed(self) -> list[ObservedSni]:
        """Aktuelle Momentaufnahme der erfassten + zugeordneten SNIs (delegiert).

        Teilt den State mit ``GetObservedSni`` (derselbe Adapter-Singleton): es gibt
        EINE Erfassung pro App. Reicht die rohen ``ObservedSni`` heraus; die Wire-
        Projektion (inkl. ``age_secs``) macht der api-Rand.
        """
        return self._sniffer.observed()


class StartSniCapture:
    """Pruefung VOR dem Sniff-Start -- liefert die ``{ok, error}``-Naht fuer 403.

    Duenn (Muster ``StartCapture``): prueft Verfuegbarkeit (scapy da?) und Berechtigung
    (``check_permission``) ueber den Port und gibt die ``{"ok", "error"}``-Form zurueck.
    Den eigentlichen Start (``RunSniCapture.start`` + ``app.state``) macht der
    Composition-Callable bei ``ok=True``; dieser Use-Case entscheidet nur, OB gestartet
    werden darf. Der Router uebersetzt ``ok=false`` in eine 403.
    """

    def __init__(self, sniffer: SniSnifferPort) -> None:
        self._sniffer = sniffer

    def __call__(self) -> dict[str, Any]:
        """``{"ok": True, "error": ""}`` wenn Sniff moeglich, sonst ``ok=False`` + Grund.

        ``is_available`` False -> scapy fehlt (libpcap-Hinweis). Sonst
        ``check_permission``: ein nicht-leerer Text ist die Rechte-Begruendung
        (``cap_net_raw``) -> ``ok=False`` (Router -> 403). ``None`` -> Sniff moeglich.
        """
        if not self._sniffer.is_available():
            return {
                "ok": False,
                "error": "SNI capture requires libpcap. Install it and restart CERNIS PRO.",
            }
        perm_error = self._sniffer.check_permission()
        if perm_error:
            return {"ok": False, "error": perm_error}
        return {"ok": True, "error": ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (fuer den status-Endpunkt)."""
        return self._sniffer.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer den status-Endpunkt ``permission_error``)."""
        return self._sniffer.check_permission()

    def stopped_reason(self) -> str | None:
        """Grund des Selbst-Abbruchs oder ``None`` (fuer den status-Endpunkt, Befund 30).

        EXAKT die Linie von ``check_permission``: ein duenner Pass-Through ueber den Port,
        der einen stabilen Marker (keinen Anzeigetext) an den status-Endpunkt reicht. Der
        Weg ist bewusst derselbe -- beide beantworten "warum geht der Mitschnitt gerade
        nicht?", nur an verschiedenen Stellen seines Lebens (vorher / mittendrin).
        """
        return self._sniffer.stopped_reason()


class GetObservedSni:
    """Liest die aktuelle Momentaufnahme der erfassten SNIs (Pass-Through ueber den Port).

    Teilt den Adapter-Singleton mit ``RunSniCapture`` (derselbe State): EINE Erfassung
    pro App. Reicht die rohen ``ObservedSni`` heraus; die ``age_secs``-Anreicherung +
    Wire-Form macht der api-Rand mit der hereingereichten ``now`` -- Naht-Linie wie der
    capture-/monitoring-Lesepfad.
    """

    def __init__(self, sniffer: SniSnifferPort) -> None:
        self._sniffer = sniffer

    def __call__(self) -> list[ObservedSni]:
        return self._sniffer.observed()
