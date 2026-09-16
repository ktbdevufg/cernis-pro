"""Ports der capture-Domaene: Vertraege fuer Live-Capture, LLDP/CDP-Discovery und
den Live-Push an die WS-Subscriber.

Drei Vertraege, gruppiert nach Belang:

* **Sniff** -- ``PacketSnifferPort`` (Dauer-Capture als async-Strom + Lifecycle),
  ``LldpSnifferPort`` (zeitbegrenzte LLDP/CDP-Erfassung).
* **Live-Push** -- ``CaptureBroadcasterPort`` (Fan-out eines ``PacketSummary`` an
  die verbundenen Subscriber, M.9-Stil).

Privilegierter scapy-Sniff (Raw-Socket/CAP_NET_RAW), Permission-Check und
``wrpcap``-Export leben hinter dem Port; der duenne Adapter kommt C.3. Das Parsen
der scapy-Pakete zu ``PacketSummary`` ist Adapter-Sache -- die Domaene und dieser
Port kennen scapy NIE, nur ``PacketSummary``/``LLDPNeighbor``.

``PacketSnifferPort.stream`` ist als nativer async-Generator modelliert (Muster
``ports.scanning.HostDiscoveryPort.discover``): der Adapter besitzt die
Sniff-Schleife und yieldet je Paket ein ``PacketSummary``; der Use-Case (C.5)
treibt daraus Statistik (``stats.apply_packet``), Ringpuffer und Broadcast -- KEIN
Callback-Geflecht wie der Altcode (``_subscribers``/``prn``). ``stop``/
``is_running`` steuern den Strom von aussen.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/monitoring). Die Vertragspruefung laeuft statisch ueber mypy und ueber die
Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

I/O-/Seiteneffekt-Methoden sind ``async`` (Sniff-Strom, LLDP-Capture, Broadcast --
der Adapter kapselt Blockierendes ueber ``run_in_executor``). ``is_running``/
``is_available`` sind reine Zustandsabfragen und damit synchron; ``stop``,
``export_pcap`` und ``check_permission`` sind lokale, schnelle Adapter-Operationen
(kein Netz-/Loop-I/O) und bleiben ebenfalls synchron, Muster zur Altcode-naehe.

``ports/`` kennt NUR ``domain/capture``-Typen + stdlib/typing. KEIN ``modules/``-
und kein ``infrastructure/``-Import -- import-linter-Contract "ports kennen
hoechstens domain". Import von ``domain`` ist erlaubt (nur die Gegenrichtung ist
verboten).
"""

from collections.abc import AsyncIterator
from typing import Protocol

from domain.capture import LLDPNeighbor, PacketSummary

# ── Sniff ─────────────────────────────────────────────────────────────────


class PacketSnifferPort(Protocol):
    """Dauer-Capture als async-Strom + Lifecycle (privilegierter scapy-Sniff)."""

    def stream(
        self, interface: str | None, bpf_filter: str, max_packets: int
    ) -> AsyncIterator[PacketSummary]:
        """Startet den Sniff und yieldet je erfasstem Paket ein ``PacketSummary``.

        Der Adapter besitzt die Sniff-Schleife und parst jedes scapy-Paket selbst
        (die Domaene sieht nie ein Rohpaket). ``interface`` ``None`` -> Default-
        Interface des Systems; ``bpf_filter`` ``""`` -> kein Filter; ``max_packets``
        begrenzt die Gesamtzahl (Altcode-``count``). Der Strom endet, wenn
        ``max_packets`` erreicht ist oder ``stop`` gerufen wurde. Ein Permission-/
        Geraete-Fehler beim Start ist ein FEHLER (keine stille Leer-Iteration) --
        der Aufrufer prueft ``check_permission``/``is_available`` vorher.
        """
        ...

    def stop(self) -> None:
        """Stoppt einen laufenden Capture-Strom (idempotent -- kein laufender
        Strom ist KEIN Fehler). Der Adapter haelt den ``AsyncSniffer`` und joint
        dessen Thread; ``stream`` endet daraufhin.
        """
        ...

    def is_running(self) -> bool:
        """``True``, solange der Sniffer-Thread tatsaechlich laeuft.

        Spiegelt den ECHTEN Thread-Zustand (Altcode: ``.running`` war unzuverlaessig,
        blieb nach Crash ``True`` -- der Adapter prueft ``thread.is_alive()``).
        """
        ...

    def export_pcap(self, path: str) -> bool:
        """Schreibt die seit Capture-Start gesammelten Rohpakete als pcap nach ``path``.

        Die scapy-Rohpakete liegen im Adapter (die Domaene kennt nur
        ``PacketSummary``). ``True`` bei erfolgreichem Schreiben, ``False`` wenn
        nichts zu schreiben war oder das Schreiben fehlschlug (best-effort wie der
        Altcode-``_save_pcap``).
        """
        ...

    def check_permission(self) -> str | None:
        """Prueft, ob Capture moeglich ist; Fehlertext oder ``None`` wenn OK.

        ``None`` heisst "Capture moeglich". Ein nicht-leerer String ist die
        plattformspezifische Begruendung samt Fix-Hinweis (Altcode-
        ``_check_capture_permission``) -- KEIN stiller Fallback (ADR 0001/S3).
        """
        ...

    def is_available(self) -> bool:
        """``True``, wenn die Capture-Backend-Bibliothek (libpcap/scapy) verfuegbar ist.

        Reiner Verfuegbarkeits-Check (Altcode-``HAS_SCAPY``), unabhaengig von
        Berechtigungen -- die prueft ``check_permission``.
        """
        ...


class LldpSnifferPort(Protocol):
    """Zeitbegrenzte LLDP/CDP-Erfassung der erreichbaren Nachbarn."""

    async def capture(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        """Lauscht ``duration`` Sekunden auf LLDP/CDP und liefert die Nachbarn.

        ``interface`` ``None`` -> Default-Interface. Blockierender scapy-``sniff``
        im Altcode; der Adapter kapselt das ueber ``run_in_executor``, die Methode
        bleibt ``async``. Keine Nachbarn entdeckt -> ``[]``, niemals ``None``. Das
        Parsen der scapy-LLDP/CDP-Layer zu ``LLDPNeighbor`` ist Adapter-Sache.
        """
        ...


# ── Live-Push ───────────────────────────────────────────────────────────────


class CaptureBroadcasterPort(Protocol):
    """Veroeffentlicht ein erfasstes Paket an die verbundenen WS-Subscriber.

    Muster ``ports.monitoring.MonitorBroadcasterPort``: Fan-out an N Subscriber,
    der Use-Case sagt nur "hier ist ein Paket", ohne die WS-Connections zu kennen.
    Subscriber-Verwaltung (subscribe/unsubscribe) und das eigentliche Fan-out
    leben im Adapter (M.9-nah, ersetzt den kaputten Altcode-``_subscribers``-Pfad).

    WICHTIG zur Naht: nimmt ein DOMAENEN-``PacketSummary``, KEIN fertiges WS-dict.
    Der Adapter baut daraus das WS-Frame (die JSON-Projektion bleibt am Rand, nicht
    im Use-Case).
    """

    async def broadcast(self, packet: PacketSummary) -> None:
        """Veroeffentlicht ``packet`` an alle aktuellen Subscriber.

        Keine Subscriber -> die Methode tut nichts (kein Fehler). Best-effort: ein
        fehlgeschlagener Push an einen einzelnen Subscriber darf den Capture-Strom
        nicht killen (der Adapter faengt/loggt).
        """
        ...
