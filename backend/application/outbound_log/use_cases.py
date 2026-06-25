"""Use-Cases der Aussenkontakte-Aufzeichnung: Lifecycle, Konfliktregel, Lesen (E3a).

NUR reine Application-Use-Cases ueber den drei outbound_log-Repos -- KEIN Worker/Sink,
KEINE Lifespan/app.py-Verdrahtung, KEIN api/Frontend (das kommt in E3b). GETRENNT in
Lifecycle (Anlegen + Zustandsuebergaenge der DEFINITIONEN) und Lesen (Definition,
Aggregat, Detail-Range, Retention).

KEINE Uhr in den Use-Cases: wo ``now``/``cutoff_ts`` gebraucht wird, kommt es als
METHODEN-Parameter herein (der Rand liefert ``time.time()``) -- so bleiben die
Use-Cases deterministisch testbar (Muster: die Domaene ist zeitfrei, der Rand liefert
die Zeit). Die Domaenen-``__post_init__`` ist die Wahrheit ueber die Wert-Invarianten
(``interval_s``, DETAIL-Deckel); die Use-Cases pruefen sie NICHT zusaetzlich.

KONFLIKT-Regel (Konzept): host-weit darf HOECHSTENS EINE Aufzeichnung gleichzeitig
``ACTIVE`` sein (KEIN ``target_id``-Bezug -- eine Aufzeichnung gilt DIESEM Host). Sie
greift erst beim STARTEN/FORTSETZEN (nicht beim Anlegen) -- beliebig viele
Aufzeichnungen sind anlegbar, der Konflikt entsteht erst, wenn eine zweite aktiv
werden will. Geprueft via ``_find_active_recording`` gegen ``list_all``.
"""

from application.outbound_log.errors import RecordingConflict, RecordingNotFound
from domain.outbound_log import (
    MAX_DETAIL_DURATION_S,
    AggregatedContact,
    DetailDepth,
    OutboundDetailRow,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)
from domain.outbound_log import (
    pause as domain_pause,
)
from domain.outbound_log import (
    resume as domain_resume,
)
from domain.outbound_log import (
    start as domain_start,
)
from domain.outbound_log import (
    stop as domain_stop,
)
from ports.outbound_log import (
    OutboundAggregateRepository,
    OutboundDetailRepository,
    OutboundRecordingRepository,
)


def _find_active_recording(others: list[OutboundRecording], exclude_id: str | None) -> str | None:
    """``id`` der ersten Aufzeichnung im Zustand ``ACTIVE`` -- oder ``None``.

    Globale Host-Regel: KEIN ``target_id``-Bezug (anders als ``_find_active_conflict``
    der monitoring-Schicht). ``exclude_id`` klammert die eigene Aufzeichnung aus, damit
    eine bereits ``ACTIVE``-Aufzeichnung nicht mit sich selbst kollidiert. Liefert die
    ID des Konkurrenten (die braucht ``RecordingConflict`` fuer die Meldung), sonst
    ``None``.
    """
    for other in others:
        if other.id != exclude_id and other.state is RecordingState.ACTIVE:
            return other.id
    return None


class CreateOutboundRecording:
    """Legt eine neue Aufzeichnung im Zustand ``CREATED`` an (reine Anlage).

    KEIN Start, KEINE Konfliktpruefung: Anlegen ist beliebig erlaubt (Konflikt erst
    beim Starten). ``recording_id`` und ``now`` kommen als Methoden-Parameter herein
    (der Rand liefert ``uuid4`` / ``time.time()``) -- der Use-Case haelt keine Uhr.
    ``created_at = now``, ``effective_start = None`` (erst der Start setzt ihn).

    DETAIL-Default-Deckel: ist ``mode == DETAIL`` und ``max_duration_s is None``, wird
    der volle 24-h-Deckel ``MAX_DETAIL_DURATION_S`` gesetzt. Ist ``mode == AGGREGATE``,
    wird ``max_duration_s`` IMMER auf ``None`` erzwungen (kein Zeitlimit) -- auch wenn
    der Aufrufer faelschlich einen Wert uebergibt. ``interval_s`` wird unveraendert
    durchgereicht: die Domaenen-``__post_init__`` validiert (``interval_s`` in
    ``ALLOWED_INTERVALS``, DETAIL-Deckel ``1..86400``) und wirft ``ValueError`` bei
    Verstoss -- NICHT hier zusaetzlich pruefen (die Domaene ist die Wahrheit).
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(
        self,
        recording_id: str,
        label: str,
        purpose: str,
        mode: RecordingMode,
        depth: DetailDepth,
        interval_s: int,
        now: float,
        max_duration_s: int | None = None,
    ) -> OutboundRecording:
        if mode is RecordingMode.AGGREGATE:
            # AGGREGATE kennt kein Zeitlimit -- einen faelschlich uebergebenen Wert
            # hart auf None zwingen (kein stiller Durchlass an die Domaene).
            effective_max_duration_s: int | None = None
        elif max_duration_s is None:
            # DETAIL ohne Vorgabe -> voller 24-h-Deckel als Default.
            effective_max_duration_s = MAX_DETAIL_DURATION_S
        else:
            effective_max_duration_s = max_duration_s
        recording = OutboundRecording(
            id=recording_id,
            label=label,
            purpose=purpose,
            mode=mode,
            depth=depth,
            state=RecordingState.CREATED,
            interval_s=interval_s,
            created_at=now,
            effective_start=None,
            max_duration_s=effective_max_duration_s,
        )
        self._repo.save(recording)
        return recording


class StartOutboundRecording:
    """Uebergang ``CREATED`` -> ``ACTIVE`` mit host-weiter Konfliktpruefung.

    Laedt die Aufzeichnung (``get``; ``None`` -> ``RecordingNotFound``), prueft via
    ``_find_active_recording`` gegen ``list_all`` (eigene ``id`` ausgeklammert), ob
    host-weit bereits eine ``ACTIVE``-Aufzeichnung laeuft -> ``RecordingConflict`` (mit
    der ``running_id`` des Konkurrenten). Sonst Domaenen-``start`` mit ``now`` als
    effektivem Start (``InvalidRecordingTransition`` aus falschem Ausgangszustand
    propagiert -- NICHT gefangen, der api-Rand mappt spaeter) -> ``save``.
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(self, recording_id: str, now: float) -> OutboundRecording:
        recording = self._repo.get(recording_id)
        if recording is None:
            raise RecordingNotFound(recording_id)
        running_id = _find_active_recording(self._repo.list_all(), exclude_id=recording_id)
        if running_id is not None:
            raise RecordingConflict(running_id)
        started = domain_start(recording, now)
        self._repo.save(started)
        return started


class PauseOutboundRecording:
    """Uebergang ``ACTIVE`` -> ``PAUSED`` (Domaenen-``pause`` -> ``save``).

    ``get`` (``None`` -> ``RecordingNotFound``), dann Domaenen-``pause``; ein
    ``InvalidRecordingTransition`` aus falschem Ausgangszustand propagiert (NICHT
    gefangen, der api-Rand mappt ihn spaeter auf 409). KEINE Konfliktpruefung --
    Pausieren entschaerft den Konflikt, es erzeugt keinen.
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(self, recording_id: str) -> OutboundRecording:
        recording = self._repo.get(recording_id)
        if recording is None:
            raise RecordingNotFound(recording_id)
        paused = domain_pause(recording)
        self._repo.save(paused)
        return paused


class ResumeOutboundRecording:
    """Uebergang ``PAUSED`` -> ``ACTIVE`` mit host-weiter Konfliktpruefung.

    Fortsetzen aus Pause reaktiviert die Aufzeichnung -- im Sinne der Host-Regel ein
    Start (host-weit nur eine aktiv). Darum prueft dieser Use-Case VOR dem ``resume``
    ebenfalls ``_find_active_recording`` gegen ``list_all`` (eigene ``id``
    ausgeklammert) -> ``RecordingConflict``. ``get`` (``None`` ->
    ``RecordingNotFound``); ``InvalidRecordingTransition`` aus falschem
    Ausgangszustand propagiert (NICHT gefangen, 409 am Rand).
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(self, recording_id: str) -> OutboundRecording:
        recording = self._repo.get(recording_id)
        if recording is None:
            raise RecordingNotFound(recording_id)
        running_id = _find_active_recording(self._repo.list_all(), exclude_id=recording_id)
        if running_id is not None:
            raise RecordingConflict(running_id)
        resumed = domain_resume(recording)
        self._repo.save(resumed)
        return resumed


class StopOutboundRecording:
    """Uebergang ``{ACTIVE, PAUSED}`` -> ``FINISHED`` (Domaenen-``stop`` -> ``save``).

    ``get`` (``None`` -> ``RecordingNotFound``), dann Domaenen-``stop``; ein
    ``InvalidRecordingTransition`` aus falschem Ausgangszustand propagiert (NICHT
    gefangen, 409 am Rand). KEINE Konfliktpruefung -- Beenden entschaerft den Konflikt.
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(self, recording_id: str) -> OutboundRecording:
        recording = self._repo.get(recording_id)
        if recording is None:
            raise RecordingNotFound(recording_id)
        finished = domain_stop(recording)
        self._repo.save(finished)
        return finished


class DeleteOutboundRecording:
    """Loescht die Aufzeichnungs-DEFINITION samt zugehoeriger Messdaten (idempotent).

    Nimmt ALLE DREI Repos: loescht die Definition (``repo_rec.delete``) UND die
    Aggregate dieser Aufzeichnung (``repo_agg.delete_for``). Beide sind idempotent
    (unbekannte ``id`` -> kein Fehler), darum ist auch dieser Use-Case idempotent.

    Fuer den DETAIL-Store gibt es BEWUSST KEIN gezieltes ``delete_for(id)``: die
    Detail-Retention laeuft zeit-basiert (``delete_older_than`` / 24-h-Deckel), ein
    gezieltes Loeschen aller Detailzeilen einer ``recording_id`` ist hier NICHT
    vorgesehen -- die Detailzeilen verfallen ohnehin durch die Retention.
    """

    def __init__(
        self,
        repo_rec: OutboundRecordingRepository,
        repo_detail: OutboundDetailRepository,
        repo_agg: OutboundAggregateRepository,
    ) -> None:
        self._repo_rec = repo_rec
        # repo_detail wird gehalten (Vollstaendigkeit der Naht), aber NICHT zum
        # gezielten Loeschen genutzt -- s. Docstring (zeit-basierte Retention).
        self._repo_detail = repo_detail
        self._repo_agg = repo_agg

    def __call__(self, recording_id: str) -> None:
        self._repo_rec.delete(recording_id)
        self._repo_agg.delete_for(recording_id)


class ListOutboundRecordings:
    """Alle Aufzeichnungs-Definitionen (Pass-Through, nur Repo).

    Reicht ``OutboundRecordingRepository.list_all`` roh durch. Leere Tabelle -> ``[]``.
    Die Wire-Form baut der api-Rand (E3b).
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(self) -> list[OutboundRecording]:
        return self._repo.list_all()


class GetOutboundRecording:
    """Eine einzelne Aufzeichnungs-Definition (``get``; ``None`` -> ``RecordingNotFound``).

    Nur die Definition -- der detail-reiche Lesepfad fuer den Bericht (Aggregat +
    Verlauf gebuendelt) kommt in E4/E6. ``get`` liefert bei unbekannter ``id`` ``None``,
    was hier in ``RecordingNotFound`` uebersetzt wird (sprechender als ein ``None`` am
    Rand).
    """

    def __init__(self, repo: OutboundRecordingRepository) -> None:
        self._repo = repo

    def __call__(self, recording_id: str) -> OutboundRecording:
        recording = self._repo.get(recording_id)
        if recording is None:
            raise RecordingNotFound(recording_id)
        return recording


class GetOutboundAggregate:
    """Der verdichtete Stand einer Aufzeichnung fuer Ansicht/Bericht (Pass-Through).

    Reicht ``OutboundAggregateRepository.list_for`` roh durch (lauteste Gegenstelle
    zuerst, s. Port). Keine Daten / unbekannte Aufzeichnung -> ``[]`` (KEIN
    ``RecordingNotFound`` -- ein leeres Aggregat ist ein legitimer Zustand).
    """

    def __init__(self, repo_agg: OutboundAggregateRepository) -> None:
        self._repo_agg = repo_agg

    def __call__(self, recording_id: str) -> list[AggregatedContact]:
        return self._repo_agg.list_for(recording_id)


class GetOutboundDetailRange:
    """Roher DETAIL-Zeitverlauf einer Aufzeichnung im Fenster (Pass-Through).

    Reicht ``OutboundDetailRepository.range`` roh durch (``[since, until)``,
    chronologisch -- s. Port). Beide Grenzen sind ABSOLUTE ts-Werte (der Use-Case haelt
    keine Uhr). Keine Daten / unbekannte Aufzeichnung -> ``[]``.
    """

    def __init__(self, repo_detail: OutboundDetailRepository) -> None:
        self._repo_detail = repo_detail

    def __call__(self, recording_id: str, since: float, until: float) -> list[OutboundDetailRow]:
        return self._repo_detail.range(recording_id, since, until)


class EnforceOutboundDetailRetention:
    """Loescht abgelaufene DETAIL-Messpunkte (Pass-Through, gibt Zeilenzahl zurueck).

    Reicht einen ABSOLUTEN Cutoff an ``OutboundDetailRepository.delete_older_than``
    durch und gibt die Zahl geloeschter Zeilen zurueck. KEINE Uhr im Use-Case: der
    Cutoff ist ``__call__``-Parameter -- der Aufrufer bildet ihn aus ``now - 24h``. Die
    Aufzeichnungs-DEFINITIONEN und die Aggregate sind NICHT betroffen (Retention raeumt
    nur den rohen DETAIL-Verlauf).
    """

    def __init__(self, repo_detail: OutboundDetailRepository) -> None:
        self._repo_detail = repo_detail

    def __call__(self, cutoff_ts: float) -> int:
        return self._repo_detail.delete_older_than(cutoff_ts)
