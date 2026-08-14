"""Snapshot-Worker der Aussenkontakte-Aufzeichnung (E3b).

Der periodische Schreibpfad: pro ``tick`` wird -- wenn eine Aufzeichnung host-weit
AKTIV ist -- der aktuelle Aussenkontakt-Snapshot DIESES Hosts geholt und je nach Modus
(DETAIL append / AGGREGATE merge-upsert) persistiert; in JEDEM Fall laeuft am Ende die
zeit-basierte DETAIL-Retention. Strukturgleich zum CVE-Drip-Worker
(``application/cve/use_cases.py`` -- ``RunCveMonitor``): ``import time`` ist erlaubt
(keine Domaenenlogik, nur die Uhr fuer den Loop, via ``now_provider`` injizierbar und so
deterministisch testbar); ``run()`` ist nur der Rahmen ``while self._running: tick();
sleep``, die ganze Logik sitzt in ``tick``.

Quellen-agnostisch: die ECHTE Snapshot-Quelle (traffic/resolver/sni) faellt erst im
Composition Root -- der Worker kennt nur das lokal definierte ``ContactSnapshotProvider``-
Callable (Muster ``BuildOutboundContacts``: kein Fremd-Domaenentyp im application-Ring).

``tick`` ist best-effort: der ganze Rumpf liegt in ``try/except``, ein Fehler wird via
``structlog.warning`` geloggt und GESCHLUCKT, nie geworfen (Muster
``MonitorLoggingSink.record`` + ``RunCveMonitor`` -- ein einzelner Fehlschlag killt den
Loop nie).
"""

import asyncio
import time
from collections.abc import Awaitable, Callable

import structlog

from domain.outbound_log import (
    ContactDelta,
    OutboundRecording,
    RecordingMode,
    is_recording_active,
    merge_contact,
)
from ports.outbound_log import (
    OutboundAggregateRepository,
    OutboundDetailRepository,
    OutboundRecordingRepository,
)

__all__ = [
    "ContactSnapshotProvider",
    "RunOutboundRecorder",
]

_logger = structlog.get_logger(__name__)

# Default-Tick-Intervall (Sekunden), wenn kein ``interval_provider`` gesetzt ist UND
# gerade keine Aufzeichnung aktiv ist (dann gibt es kein ``rec.interval_s``).
DEFAULT_INTERVAL_S = 60

# Quellen-agnostische Naht: liefert den AKTUELLEN Aussenkontakt-Snapshot DIESES Hosts
# als ContactDelta-Liste (eine je eindeutiger Remote-IP, bereits angereichert +
# gruppiert). Lokal definiertes Callable, KEIN Fremd-Domaenentyp -- die echte Quelle
# (traffic/resolver/sni) faellt erst im Composition Root (Muster BuildOutboundContacts).
ContactSnapshotProvider = Callable[[], Awaitable[list[ContactDelta]]]


class RunOutboundRecorder:
    """Periodischer Snapshot-Worker: schreibt je Tick den Aussenkontakt-Stand fort.

    Anders als der CVE-Worker (fixes Intervall aus dem Bestand) haengt das Tick-Intervall
    hier an der GERADE aktiven Aufzeichnung (``rec.interval_s``) -- darum kein fixes
    ``interval``-Feld, sondern ``_current_interval``. Ein optionaler
    ``interval_provider`` hat Vorrang (Test/Override).
    """

    def __init__(
        self,
        recordings: OutboundRecordingRepository,
        detail: OutboundDetailRepository,
        aggregate: OutboundAggregateRepository,
        snapshot_provider: ContactSnapshotProvider,
        retention_max_age_s: int = 86400,
        interval_provider: Callable[[], int] | None = None,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._recordings = recordings
        self._detail = detail
        self._aggregate = aggregate
        self._snapshot_provider = snapshot_provider
        self._retention_max_age_s = retention_max_age_s
        self._interval_provider = interval_provider
        self._now = now_provider
        self._running = False
        # Fehlerzustand des Loop (S88-P4, Muster ``RunThroughputPoll._last_error``):
        # Wortlaut des letzten gescheiterten Durchlaufs + Zahl der AUFEINANDERFOLGENDEN
        # Fehlschlaege. Ein gelungener Durchlauf setzt beides zurueck.
        self._last_error: str | None = None
        self._consecutive_failures = 0

    def _active_recording(self, now: float) -> OutboundRecording | None:
        """Erste host-weit AKTIVE Aufzeichnung zum Zeitpunkt ``now`` (oder ``None``).

        Geht ``recordings.list_all()`` durch und gibt die ERSTE zurueck, fuer die
        ``is_recording_active(rec, now)`` True ist. Host-weit gibt es hoechstens eine
        ACTIVE (E3a-Konfliktregel garantiert das); der Worker verlaesst sich darauf,
        prueft aber defensiv nur "erste aktive".

        ``is_recording_active`` prueft ``state == ACTIVE`` UND (bei DETAIL) das
        Zeitfenster -- eine DETAIL-Aufzeichnung, deren 24-h-Fenster abgelaufen ist, ist
        damit automatisch NICHT mehr aktiv (sie wird NICHT mehr geschrieben). Sie wird
        hier NICHT automatisch auf FINISHED gesetzt -- das ist Sache des Stop-Use-Case /
        der UI; der Worker ignoriert sie nur.
        """
        for rec in self._recordings.list_all():
            if is_recording_active(rec, now):
                return rec
        return None

    async def tick(self) -> None:
        """Eine Iteration (best-effort): Snapshot schreiben (falls aktiv) + Retention.

        Der GANZE Rumpf liegt in ``try/except``: ein Fehler (z. B. ein werfender
        Snapshot-Provider oder Repo) wird geloggt und GESCHLUCKT, nie geworfen (Muster
        ``RunCveMonitor`` / ``MonitorLoggingSink.record``).
        """
        try:
            now = self._now()
            rec = self._active_recording(now)
            if rec is not None:
                deltas = await self._snapshot_provider()
                if rec.mode is RecordingMode.DETAIL:
                    for delta in deltas:
                        # ContactDelta hat KEIN pid-Feld (es traegt app_name); der
                        # Detail-Store hat aber eine pid-Spalte. Wir uebergeben pid=None:
                        # die App-Zuordnung steckt in app_name, pid ist im Aggregat-/
                        # Delta-Modell nicht gefuehrt.
                        self._detail.save(
                            rec.id,
                            now,
                            delta.remote_ip,
                            delta.remote_port,
                            delta.hostname,
                            delta.country,
                            delta.operator,
                            delta.asn,
                            delta.app_name,
                            None,
                            delta.connection_count,
                        )
                else:
                    for delta in deltas:
                        existing = self._aggregate.get(rec.id, delta.remote_ip)
                        merged = merge_contact(existing, delta, now)
                        self._aggregate.upsert(rec.id, merged)
            # IMMER zum Schluss (egal ob aktiv oder nicht): DETAIL-Retention. So
            # verfaellt roher Detail-Verlauf zuverlaessig nach ``retention_max_age_s``,
            # auch ueber mehrere Aufzeichnungen / Neustarts hinweg.
            cutoff = now - self._retention_max_age_s
            self._detail.delete_older_than(cutoff)
        except Exception as exc:
            # Best-effort: ein Tick-Fehler darf den Loop nie killen.
            _logger.warning("outbound_recorder_tick_failed", error=str(exc))

    def _current_interval(self, rec: OutboundRecording | None) -> int:
        """Tick-Intervall (Sekunden): Provider-Override > aktive Aufzeichnung > Default.

        ``interval_provider`` (Test/Override) hat Vorrang. Sonst das ``interval_s`` der
        gerade aktiven Aufzeichnung; ist keine aktiv (``rec`` None), der Default 60.
        """
        if self._interval_provider is not None:
            return self._interval_provider()
        if rec is not None:
            return rec.interval_s
        return DEFAULT_INTERVAL_S

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Die Logik sitzt in ``tick``.

        SCHUTZ UM DEN DURCHLAUF (S88-P4): ``tick`` faengt seinen ganzen Rumpf schon selbst
        -- der Schutz hier liegt eine Ebene HOEHER und deckt das ab, was im run-Rumpf
        AUSSERHALB von ``tick`` steht: ``_active_recording`` (Repo-Zugriff) und
        ``_current_interval`` (fremdes Callable ``interval_provider``). Genau dort riss
        der Task bisher, und die Ausnahme lag danach unbeachtet im Task-Objekt.
        Doppelt gefangen ist hier kein Mangel, sondern zwei verschiedene Flaechen.
        ``CancelledError`` bleibt unangetastet (Teardown-Signal, kein Fehler).

        Der Schutz sitzt bewusst im run-Rumpf jedes Arbeiters und NICHT in einer
        gemeinsamen Basisklasse: die fuenf so abgesicherten Arbeiter liegen in vier
        verschiedenen application-Subpaketen (cve, outbound_log, scheduler, monitoring);
        eine gemeinsame Basis waere ein Quer-Import zwischen ihnen oder eine neue Schicht
        unterhalb von ``application/``.

        Schlaegt der Rumpf fehl, wird mit dem Intervall des Ruhefalls weitergeschlafen
        (``_current_interval(None)``): das Intervall der aktiven Aufzeichnung ist gerade
        nicht ermittelbar, und ein enger Wiederholtakt auf eine kaputte Naht waere Last
        ohne Gewinn. Ueber ``_current_interval`` und nicht ueber die blanke Konstante,
        damit ein gesetzter ``interval_provider`` (Test/Override) auch im Fehlerfall gilt
        -- sonst haette der Fehlerpfad einen anderen Takt als der Normalfall.
        """
        self._running = True
        while self._running:
            try:
                await self.tick()
                rec = self._active_recording(self._now())
                interval = self._current_interval(rec)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # Grund wird gemerkt, nicht verschluckt (S3)
                self._note_failure(exc)
                interval = self._current_interval(None)
            else:
                self._note_success()
            await asyncio.sleep(interval)

    def _note_failure(self, exc: Exception) -> None:
        """Merkt den Wortlaut des gescheiterten Durchlaufs und zaehlt die Serie hoch."""
        self._last_error = str(exc)
        self._consecutive_failures += 1
        _logger.warning(
            "outbound_recorder_run_failed",
            error=self._last_error,
            consecutive_failures=self._consecutive_failures,
        )

    def _note_success(self) -> None:
        """Setzt Wortlaut und Zaehler nach einem gelungenen Durchlauf zurueck."""
        self._last_error = None
        self._consecutive_failures = 0

    def last_error(self) -> str | None:
        """Wortlaut des letzten gescheiterten Durchlaufs, sonst ``None`` (S88-P4).

        Bezieht sich auf den run-Rumpf, NICHT auf ``tick``: ``tick`` faengt seine Fehler
        selbst und meldet sie nur ins Log (best-effort, unveraendert).
        """
        return self._last_error

    def consecutive_failures(self) -> int:
        """Zahl der AUFEINANDERFOLGENDEN gescheiterten Durchlaeufe (0 = letzter gelang)."""
        return self._consecutive_failures

    def stop(self) -> None:
        """Setzt das Loop-Flag (Abbruch nach der laufenden Iteration)."""
        self._running = False
