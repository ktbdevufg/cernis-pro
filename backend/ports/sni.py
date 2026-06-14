"""Port der sni-Domaene: Vertrag fuer den passiven SNI-Sniff (Lifecycle + Abruf).

EIN Vertrag, ``SniSnifferPort``. Anders als ``ports.capture.PacketSnifferPort``
(Dauer-Capture als async-STROM) ist dieser Port ein AGGREGAT, kein Strom: der
Adapter haelt die erfassten ``ObservedSni``-Rohdaten + die periodischen Socket-
Snapshots INTERN (zwei Hintergrund-Threads -- der scapy-``AsyncSniffer`` und der
psutil-Poller, Lehre aus dem Spike) und liefert die zugeordnete Momentaufnahme auf
Abruf (``observed``). Damit braucht es KEINEN async-Strom und kein Callback-Geflecht
im Use-Case -- der Lesepfad zieht einfach die aktuelle Liste.

Lifecycle (``start``/``stop``/``is_running``) folgt dem Geist von
``PacketSnifferPort``, aber MANUELL und ohne Strom: ``start`` spinnt die
Hintergrund-Threads auf, ``stop`` haelt sie an (idempotent), ``is_running``
spiegelt den echten Thread-Zustand. ``check_permission``/``is_available`` folgen dem
capture-Muster (Raw-Socket-Probe bzw. scapy-Verfuegbarkeit) -- die StartSni-Naht
prueft sie VOR dem Start und uebersetzt einen Permission-Fehler in eine ehrliche 403
(KEIN stiller Fallback, ADR 0001/S3).

Alle Methoden sind SYNCHRON: ``start``/``stop`` sind schnelle, lokale Adapter-
Operationen (Threads aufspinnen/joinen, kein Netz-/Loop-I/O -- der eigentliche Sniff
laeuft im scapy-Thread, nicht in einer Coroutine), ``observed`` ist ein In-Memory-
Snapshot + reine Zuordnung, ``is_running``/``is_available``/``check_permission`` sind
Zustands-/Verfuegbarkeitsabfragen. Das ``asyncio.create_task``/``app.state``-Geruest
fuer den Lebenszyklus baut der Composition Root (Muster traffic poll/start), nicht
dieser Port.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/capture/traffic). Die Vertragspruefung laeuft statisch ueber mypy und ueber
die Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

``ports/`` kennt NUR ``domain/sni``-Typen + stdlib/typing. KEIN ``modules/``- und kein
``infrastructure/``-Import -- import-linter-Contract "ports kennen hoechstens domain".
"""

from typing import Protocol

from domain.sni import ObservedSni


class SniSnifferPort(Protocol):
    """Lifecycle eines passiven SNI-Sniffs + Abruf der zugeordneten Momentaufnahme."""

    def start(self, interface: str | None) -> None:
        """Startet den passiven Sniff (MANUELL) -- spinnt die Hintergrund-Threads auf.

        ``interface`` ``None`` -> der Adapter ermittelt das Ausgangs-Interface selbst
        (Default-Route, Muster Spike-``_pick_iface``). Der Adapter startet den
        scapy-``AsyncSniffer`` (filtert ``tcp port 443``, parst das ClientHello, haengt
        die rohen Hits an) UND einen eigenen psutil-Poller-Thread (periodische
        ``(ip,port)->pid``-Snapshots). Ein Permission-/Start-Fehler ist ein FEHLER
        (``SniError`` aus dem Adapter), KEINE stille Leer-Erfassung -- der Aufrufer
        prueft ``check_permission``/``is_available`` vorher. Bereits laufender Sniff ->
        kein Doppelstart (der Adapter ist idempotent gegenueber einem aktiven Lauf).
        """
        ...

    def stop(self) -> None:
        """Stoppt einen laufenden Sniff (idempotent -- kein laufender Sniff ist KEIN
        Fehler). Haelt den ``AsyncSniffer`` und den Poller-Thread an und joint sie.
        Die bereits erfassten Daten bleiben fuer einen letzten ``observed``-Abruf
        erhalten (der Adapter leert seinen Puffer erst beim naechsten ``start``).
        """
        ...

    def is_running(self) -> bool:
        """``True``, solange der Sniffer-Thread tatsaechlich laeuft.

        Spiegelt den ECHTEN Thread-Zustand (Muster ``PacketSnifferPort.is_running``:
        ``thread.is_alive()``, nicht ein separates Flag, das nach einem Crash
        haengenbleiben kann).
        """
        ...

    def observed(self) -> list[ObservedSni]:
        """Aktuelle Momentaufnahme der erfassten + zugeordneten SNIs.

        Der Adapter nimmt seine internen rohen Hits + die periodischen Socket-
        Snapshots und ordnet JEDEM Hit den zeitlich naechstgelegenen passenden
        Snapshot zu (Domaenen-Funktion ``match_snapshot``), loest die PID -> Name auf
        (psutil, NACH dem Match -- nie im Sniff-/Poller-Pfad) und liefert
        vollstaendige ``ObservedSni``. Nicht zuordenbare Hits behalten
        ``app_name``/``pid``/``delta_ms`` ``None`` (ehrlich, kein Verwerfen). Keine
        Hits -> ``[]``, niemals ``None``.
        """
        ...

    def check_permission(self) -> str | None:
        """Prueft, ob der passive Sniff moeglich ist; Fehlertext oder ``None`` wenn OK.

        ``None`` heisst "Sniff moeglich". Ein nicht-leerer String ist die plattform-
        spezifische Begruendung samt Fix-Hinweis (Raw-Socket-Recht/``CAP_NET_RAW``,
        Muster ``ports.capture.check_permission``) -- KEIN stiller Fallback (ADR 0001/
        S3). Schnelle lokale Pruefung, daher synchron.
        """
        ...

    def is_available(self) -> bool:
        """``True``, wenn die Sniff-Backend-Bibliothek (libpcap/scapy) verfuegbar ist.

        Reiner Verfuegbarkeits-Check (Muster ``ports.capture.is_available``: scapy da?),
        unabhaengig von Berechtigungen -- die prueft ``check_permission``.
        """
        ...
