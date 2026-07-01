"""Puffer-Leerpump-Worker des netzweiten DNS-Umgehungs-Waechters (ADR 0042, Etappe 4a).

Der laufende Aufzeichnungs-Kern: startet die DNS-Quelle, leert regelmaessig deren
gepushten Query-Puffer (``poll_queries``) und akkumuliert die rohen Anfragen im Speicher,
solange die Aufzeichnung laeuft. WICHTIGER UNTERSCHIED zum outbound_log-Recorder: der
DNS-Sniffer PUSHT Queries in eine deque (der Quell-``poll_queries`` leert sie) -- dieser
Recorder ist daher KEIN periodischer Snapshot-Worker, sondern ein PUFFER-LEERPUMP-Worker.
Die Verdichtung (``BuildDnsBypass``) passiert NICHT hier, sondern erst bei Abruf in 4b.
Schlanker als der outbound_log-Recorder: KEINE SQLite-Stores, KEINE Modi -- der laufende
Zustand haelt die gesammelten Queries im Speicher.

Strukturell wie ``RunOutboundRecorder``: ``import time`` ist erlaubt (keine Domaenenlogik,
nur die Uhr fuer den Loop, via ``now_provider`` injizierbar und so deterministisch
testbar); ``run()`` ist nur der Rahmen ``while self._active: tick(); sleep``, die ganze
Arbeit sitzt in ``tick``.

Quellen-agnostisch: die ECHTE DNS-Quelle (der ``DnsHelperClient``) faellt erst im
Composition Root (4b) -- der Recorder kennt nur das lokal definierte ``DnsQuerySource``-
Protocol (Muster ``ContactSnapshotProvider``: kein Fremd-Adapter im application-Ring, der
infrastructure-Client wird NICHT importiert).

``tick`` ist best-effort: der ganze Rumpf liegt in ``try/except``, ein Fehler wird via
``structlog.warning`` geloggt und GESCHLUCKT, nie geworfen (Muster
``RunOutboundRecorder.tick`` -- ein werfendes ``poll_queries`` killt den Loop nie).
"""

import asyncio
import time
from collections.abc import Callable
from typing import Any, Protocol

import structlog

from domain.dns_bypass import RawDnsQuery

__all__ = [
    "DnsBypassRecorder",
    "DnsQuerySource",
]

_logger = structlog.get_logger(__name__)


class DnsQuerySource(Protocol):
    """Schmale, lokal definierte Naht zur DNS-Quelle (Muster ``ContactSnapshotProvider``).

    Genau die ``DnsHelperClient``-Schnittstelle -- aber als lokales Protocol, damit der
    application-Ring den infrastructure-Client NICHT importiert. Die echte Verdrahtung
    faellt erst im Composition Root (4b).
    """

    def start(self, interface: str | None) -> str | None:
        """Startet die Quelle. ``None`` bei Erfolg, sonst ein Fehlertext."""
        ...

    def poll_queries(self) -> list[dict[str, Any]]:
        """Leert den Query-Puffer und gibt die rohen Query-dicts zurueck."""
        ...

    def stop(self) -> None:
        """Stoppt die Quelle (idempotent)."""
        ...

    def is_running(self) -> bool:
        """Ob die Quelle gerade laeuft."""
        ...


class DnsBypassRecorder:
    """Puffer-Leerpump-Worker: pumpt ``poll_queries`` in einen Speicher-Puffer.

    Quellen-AGNOSTISCH (Muster ``RunOutboundRecorder``): bekommt eine ``DnsQuerySource``
    per Constructor-Injection -- der Recorder nennt keinen infrastructure-Client. Der
    laufende Zustand (die gesammelten ``RawDnsQuery``) lebt im Speicher, KEIN SQLite.

    ``run()`` ist nur der Rahmen ``while self._active: tick(); sleep`` -- die Arbeit sitzt
    in ``tick``, best-effort: ein werfendes ``poll_queries`` wird geloggt und geschluckt,
    der Loop laeuft weiter.
    """

    def __init__(
        self,
        source: DnsQuerySource,
        poll_interval_s: int = 2,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._source = source
        self._poll_interval_s = poll_interval_s
        self._now = now_provider
        self._active = False
        self._interface: str | None = None
        self._collected: list[RawDnsQuery] = []

    def start(self, interface: str | None) -> str | None:
        """Startet die Quelle + oeffnet die Aufzeichnung. ``None`` = ok, sonst Fehlertext.

        Kein Doppelstart: laeuft die Aufzeichnung schon, ``None`` zurueck. Sonst
        ``source.start(interface)``; bei Fehlertext bleibt der Recorder NICHT aktiv und
        gibt den Text durch. Bei Erfolg wird der Sammelpuffer geleert, ``aktiv=True``
        gesetzt und ``None`` zurueckgegeben.
        """
        if self._active:
            return None
        error = self._source.start(interface)
        if error is not None:
            return error
        self._collected = []
        self._interface = interface
        self._active = True
        return None

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Die Arbeit sitzt in ``tick``."""
        while self._active:
            await self.tick()
            await asyncio.sleep(self._poll_interval_s)

    async def tick(self) -> None:
        """Eine Iteration (best-effort): Query-Puffer der Quelle in den Sammelpuffer pumpen.

        Der GANZE Rumpf liegt in ``try/except``: ``source.poll_queries()`` abrufen, jedes
        rohe dict auf ``RawDnsQuery`` mappen (``src_ip``/``dst_ip``/``l4`` Pflicht; ``qname``
        optional -> ``""`` wenn fehlt) und an den Sammelpuffer anhaengen. Ein Fehler (z. B.
        ein werfendes ``poll_queries``) wird geloggt und GESCHLUCKT, nie geworfen (Muster
        ``RunOutboundRecorder.tick``).
        """
        try:
            for raw in self._source.poll_queries():
                self._collected.append(
                    RawDnsQuery(
                        src_ip=raw["src_ip"],
                        dst_ip=raw["dst_ip"],
                        l4=raw["l4"],
                        qname=raw.get("qname", ""),
                    )
                )
        except Exception as exc:
            # Best-effort: ein Tick-Fehler darf den Loop nie killen.
            _logger.warning("dns_bypass_recorder_tick_failed", error=str(exc))

    def stop(self) -> None:
        """Beendet die Aufzeichnung: ``aktiv=False``, dann ``source.stop()`` (best-effort)."""
        self._active = False
        self._source.stop()

    def snapshot_queries(self) -> list[RawDnsQuery]:
        """Gibt eine KOPIE des aktuellen Sammelpuffers zurueck (fuer 4b: ``BuildDnsBypass``)."""
        return list(self._collected)

    def is_active(self) -> bool:
        """Ob gerade eine Aufzeichnung laeuft."""
        return self._active

    def clear(self) -> None:
        """Leert den Sammelpuffer (fuer einen sauberen Neustart einer Aufzeichnung)."""
        self._collected = []
