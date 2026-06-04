"""Use-Cases der capture-Domaene -- Live-Capture-Loop + LLDP/CDP-Erfassung (C.4+5).

Fuehrt den Altcode-State (``modules/pcap.py`` globale ``_capture_*`` / ``modules/
lldp.py`` ``_neighbors``) als saubere Use-Cases zusammen: die reine Domaenenlogik
(``apply_packet`` / ``ring_trim`` / ``stats_to_view`` / ``neighbor_age``, C.1+2),
die drei Ports (C.1+2) und -- ueber die Ports -- die scapy-Adapter (C.3). Kennt
``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` oder ``modules/``
(maschinell per import-linter erzwungen). Alle Ports kommen per Constructor-
Injection als Protocol-Typ herein. Kein Framework-Import, KEIN ``asyncio.Task``-
Management: ``RunCapture`` bietet ``run()``/``stop()``, das ``create_task``/Teardown
treibt der Composition Root (``app.py``-Callable + lifespan, C.5) -- Muster wie
``RunMonitor``.

STATE-HALTER (anders als die monitoring-Lese-Use-Cases): Der C.3-Sniffer-Adapter
haelt NUR die scapy-Rohpakete (fuer ``wrpcap``). Den ``PacketSummary``-Ringpuffer
und die fortgeschriebene ``CaptureStats`` haelt der ``RunCapture``-Use-Case selbst
(Vorgabe C.4: "der Use-Case treibt apply_packet + ring_trim + Broadcast"). Ebenso
haelt ``CaptureLldp`` die In-Memory-Nachbartabelle (``mac -> LLDPNeighbor``), die im
Altcode das Modul-globale ``_neighbors`` war -- der zeitbegrenzte
``LldpSnifferPort.capture`` gibt nur eine Momentaufnahme, die Akkumulation lebt hier.

Naht-Linie wie ``RunMonitor``/Broadcaster: der Use-Case gibt rohe Domaenen-Daten,
der api-Rand baut die Wire-Form (``_packet_to_dict`` / ``_neighbor_to_dict``).
"""

from typing import Any

import structlog

from domain.capture import (
    CaptureStats,
    LLDPNeighbor,
    PacketSummary,
    apply_packet,
    neighbor_age,
    ring_trim,
)
from ports.capture import CaptureBroadcasterPort, LldpSnifferPort, PacketSnifferPort

_logger = structlog.get_logger(__name__)


class RunCapture:
    """Treibt den Live-Capture-Loop und haelt Stats + Paket-Ringpuffer (Singleton).

    Eine langlebige Instanz pro App (wie ``RunMonitor``): ``run()`` iteriert ueber
    den Sniffer-Strom, schreibt jedes Paket in die Statistik (``apply_packet``) und
    den Ringpuffer (``ring_trim`` 10000->5000) fort und broadcastet es. ``status``/
    ``recent_packets`` lesen diesen State -- so sehen die REST-Lesepfade
    (``/api/pcap/status`` + ``/api/pcap/packets``) denselben Zustand wie der laufende
    Loop, exakt wie der Altcode-Modul-State.
    """

    def __init__(
        self,
        sniffer: PacketSnifferPort,
        broadcaster: CaptureBroadcasterPort,
        pcap_path: str,
    ) -> None:
        self._sniffer = sniffer
        self._broadcaster = broadcaster
        # Ziel-Pfad der temp-pcap, die ``stop()`` schreibt (altcode-treu: der
        # Altcode-``stop_capture`` rief ``_save_pcap`` automatisch). ``status``/``save``
        # lesen den geschriebenen Pfad ueber ``self._saved_pcap_path``.
        self._pcap_path = pcap_path
        self._saved_pcap_path: str | None = None
        # Loop-State, ueber die Iterationen gehalten (Altcode: _capture_stats /
        # _capture_packets). Frische Stats je run() (Reset im run-Einstieg).
        self._stats = CaptureStats()
        self._packets: list[PacketSummary] = []

    async def run(self, interface: str | None, bpf_filter: str, max_packets: int) -> None:
        """Iteriert ueber den Sniffer-Strom: Stats fortschreiben, puffern, broadcasten.

        Reset von Stats + Ringpuffer + gemerktem pcap-Pfad beim Start (ein run() ist
        ein frischer Capture). Der Strom endet, wenn ``max_packets`` erreicht ist
        oder ``stop()`` gerufen wurde; ein Start-Fehler (Rechte/Geraet) propagiert
        als ``CaptureError`` aus ``stream`` -- der Aufrufer (StartCapture-Naht) prueft
        ``check_permission`` vorher.
        """
        self._stats = CaptureStats()
        self._packets = []
        self._saved_pcap_path = None
        async for ps in self._sniffer.stream(interface, bpf_filter, max_packets):
            self._stats = apply_packet(self._stats, ps)
            self._packets.append(ps)
            self._packets = ring_trim(self._packets)
            await self._broadcaster.broadcast(ps)

    def stop(self) -> None:
        """Stoppt den Capture und schreibt die temp-pcap (altcode-treu).

        Reihenfolge wie der Altcode-``stop_capture``: erst die gesammelten Rohpakete
        als pcap nach ``self._pcap_path`` exportieren (``export_pcap``), den Pfad
        merken (nur bei Erfolg -- ``export_pcap`` ist best-effort und gibt ``False``,
        wenn nichts zu schreiben war), dann den Sniffer-Thread stoppen. So ist die
        pcap direkt nach dem Stop fuer ``status``/``save`` verfuegbar.
        """
        if self._sniffer.export_pcap(self._pcap_path):
            self._saved_pcap_path = self._pcap_path
        self._sniffer.stop()

    def is_running(self) -> bool:
        """``True``, solange der Sniffer-Thread laeuft (delegiert an den Adapter)."""
        return self._sniffer.is_running()

    def status(self, now: float) -> dict[str, Any]:
        """Aktueller Capture-Status als Wire-naher dict (Altcode-``get_capture_status``).

        Felder exakt wie der C.0-Contract (``running``, ``packets``, ``stats``,
        ``pcap_available``, ``pcap_path``, ``error``). ``stats`` ist die sortierte/
        gekappte Sicht (``stats_to_view``, ``now`` hereingereicht). ``error`` bleibt
        IMMER ``""``: der Altcode setzte ``_capture_error`` nie -- totes Feld,
        AS-IS bewahrt (Phase-4-Kandidat, nicht hier heilen).
        """
        from domain.capture import stats_to_view

        return {
            "running": self.is_running(),
            "packets": len(self._packets),
            "stats": stats_to_view(self._stats, now),
            "pcap_available": self._saved_pcap_path is not None,
            "pcap_path": self._saved_pcap_path,
            "error": "",  # totes Feld (Altcode setzte _capture_error nie), Phase-4.
        }

    def recent_packets(self, limit: int) -> list[PacketSummary]:
        """Die letzten ``limit`` Pakete des Ringpuffers (Altcode ``get_recent_packets``)."""
        return self._packets[-limit:]

    def pcap_path(self) -> str | None:
        """Der Pfad der zuletzt geschriebenen temp-pcap (``None``, wenn keine).

        Speist den ``save``-Pfad (Composition Root kopiert von hier). ``None``, wenn
        noch kein ``stop()`` mit Paketen lief -- der Router antwortet dann mit 404.
        """
        return self._saved_pcap_path


class StartCapture:
    """Pruefung VOR dem Capture-Start -- liefert die ``{ok, error}``-Naht fuer 403.

    Duenn (Muster der monitoring-Pass-Throughs): prueft Verfuegbarkeit (scapy da?)
    und Berechtigung (``check_permission``) ueber den Sniffer-Port und gibt die
    Altcode-``{"ok", "error"}``-Form zurueck. Den eigentlichen ``asyncio.create_task
    (run_capture.run(...))`` macht der Composition Root (api darf kein ``create_task``
    /``app.state``); dieser Use-Case entscheidet nur, OB gestartet werden darf, und
    der Composition-Callable startet bei ``ok=True`` den Loop.
    """

    def __init__(self, sniffer: PacketSnifferPort) -> None:
        self._sniffer = sniffer

    def __call__(self) -> dict[str, Any]:
        """``{"ok": True, "error": ""}`` wenn Capture moeglich, sonst ``ok=False`` + Grund.

        ``is_available`` False -> scapy fehlt (libpcap-Hinweis). Sonst
        ``check_permission``: ein nicht-leerer Text ist die Rechte-Begruendung
        (cap_net_raw) -> ``ok=False`` (Router uebersetzt das in 403). ``None`` ->
        Capture moeglich.
        """
        if not self._sniffer.is_available():
            return {
                "ok": False,
                "error": "Packet Capture requires libpcap. Install it and restart CERNIS PRO.",
            }
        perm_error = self._sniffer.check_permission()
        if perm_error:
            return {"ok": False, "error": perm_error}
        return {"ok": True, "error": ""}

    def is_available(self) -> bool:
        """Reiner Verfuegbarkeits-Check (Altcode ``check_available``) fuer ``/available``."""
        return self._sniffer.is_available()

    def check_permission(self) -> str | None:
        """Rechte-Begruendung oder ``None`` (fuer ``/available`` ``permission_error``)."""
        return self._sniffer.check_permission()


class CaptureLldp:
    """Zeitbegrenzte LLDP/CDP-Erfassung -- akkumuliert die Nachbartabelle (Singleton).

    Ruft ``LldpSnifferPort.capture`` (zeitbegrenzter Sniff) und MERGT die Funde in
    eine In-Memory-Map ``mac -> LLDPNeighbor`` (letzter Eintrag je MAC gewinnt,
    ``last_seen`` aktualisiert). Das ersetzt das Altcode-Modul-globale ``_neighbors``
    -- der Sniffer-Adapter haelt KEINE persistente Tabelle (er gibt nur eine
    Momentaufnahme). Kein Expiry: die Map waechst monoton (altcode-treu, Phase-4-
    Kandidat). ``capture`` gibt die frisch erfassten Nachbarn der Runde zurueck.
    """

    def __init__(self, sniffer: LldpSnifferPort) -> None:
        self._sniffer = sniffer
        # mac -> Nachbar (akkumuliert ueber alle capture-Runden). GetLldpNeighbors liest.
        self._neighbors: dict[str, LLDPNeighbor] = {}

    async def __call__(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        """Sniff ``duration`` Sekunden, merge in die Map, gib die Runden-Funde zurueck."""
        found = await self._sniffer.capture(interface, duration)
        for neighbor in found:
            self._neighbors[neighbor.source_mac] = neighbor
        return found

    @property
    def neighbors(self) -> dict[str, LLDPNeighbor]:
        """Die akkumulierte Nachbartabelle (von ``GetLldpNeighbors`` gelesen)."""
        return self._neighbors


class GetLldpNeighbors:
    """Liest die akkumulierte Nachbartabelle (Pass-Through ueber ``CaptureLldp``-State).

    Teilt sich die ``CaptureLldp``-Instanz (denselben State): es gibt EINE
    Nachbartabelle pro App. Reicht die Werte als rohe ``LLDPNeighbor`` heraus; die
    ``age_secs``/``expired``-Anreicherung (``neighbor_age``) macht der api-Rand mit
    der hereingereichten ``now`` -- Naht-Linie wie der Broadcaster/RunMonitor.
    """

    def __init__(self, capture_lldp: CaptureLldp) -> None:
        self._capture_lldp = capture_lldp

    def __call__(self) -> list[LLDPNeighbor]:
        return list(self._capture_lldp.neighbors.values())


def enrich_neighbor(neighbor: LLDPNeighbor, now: float) -> tuple[int, bool]:
    """``age_secs``/``expired`` eines Nachbarn (``neighbor_age``-Wrapper fuer den Rand).

    Liegt hier (application), damit der api-Rand die domain-Funktion ``neighbor_age``
    nicht direkt importieren muss (api -> nur application). Reicht ``now`` und die
    Nachbar-Felder durch -- reine Pass-Through-Anreicherung.
    """
    return neighbor_age(now, neighbor.last_seen, neighbor.ttl)
