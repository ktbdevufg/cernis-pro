"""Aufzeichnung der Aussenkontakte DIESES Hosts ueber Zeit -- reine, zeitfreie Logik.

Eine vom Nutzer gestartete Aufzeichnung, WELCHE entfernten Gegenstellen dieser Host
ueber die Zeit kontaktiert. Strukturgleich zur Logging-Aufgabe der monitoring-Domaene
(``domain/monitoring/logging_task.py``), aber bewusst EIGENSTAENDIG: KEIN Import aus
``domain.monitoring`` oder einer anderen Domaene (independence-Contract). Die Datei
definiert nur, WAS eine Aufzeichnung ist und die reinen Zustands-/Zeitfenster-Regeln
darueber -- sie kennt KEINE Persistenz, KEINEN Loop, KEINE Uhr: jede zeitabhaengige
Frage bekommt ``now`` als Parameter (kein ``time.time()`` in der Domaene -- ADR 0002,
stdlib only, framework-frei).

Muster konsequent aus der Nachbarschaft uebernommen: frozen dataclasses + StrEnum,
eigenstaendiger Domaenen-Fehler (``InvalidRecordingTransition`` erbt von ``Exception``,
NICHT von ``ValueError`` -- analog ``InvalidTaskTransition``), Zustandsuebergaenge als
reine Funktionen, die via ``dataclasses.replace`` ein NEUES Objekt zurueckgeben (kein
In-Place-Mutieren auf einer frozen dataclass). ``float``-Zeitstempel sind Unix-ts.
"""

import dataclasses
from dataclasses import dataclass
from enum import StrEnum

# Harte 24-h-Obergrenze fuer den DETAIL-Modus: der volle rohe Zeitverlauf bleibt
# zeitbegrenzt (Speicher-/Datenschutz-Deckel), in der Domaene erzwungen.
MAX_DETAIL_DURATION_S = 86400

# Erlaubte Mess-Intervalle (Sekunden) und der Default. Ausserhalb dieser Menge ist
# kein Intervall zulaessig (harte Validierung in ``__post_init__``).
ALLOWED_INTERVALS = (30, 60, 300)
DEFAULT_INTERVAL_S = 60


class RecordingMode(StrEnum):
    """WIE eine Aufzeichnung die Aussenkontakte ablegt.

    ``DETAIL``: voller roher Zeitverlauf, zeitbegrenzt (Fenster ab ``effective_start``
    fuer hoechstens ``max_duration_s`` Sekunden, gedeckelt durch
    ``MAX_DETAIL_DURATION_S``). ``AGGREGATE``: pro Remote-IP ein fortlaufender
    verdichteter Datensatz ohne Zeitlimit (langlebig).
    """

    DETAIL = "detail"
    AGGREGATE = "aggregate"


class DetailDepth(StrEnum):
    """Gewuenschte Rechte-Tiefe der Zuordnung -- orthogonal zum Modus.

    ``ANONYMOUS`` (rootlos): Kontakte ohne garantierte App/Prozess-Zuordnung.
    ``APP_RESOLVED`` (root): volle App/Prozess-Zuordnung. Reiner Datentraeger-Marker
    -- die Domaene erzwingt KEINE Rechte (kein Self-Escalate); ob root real vorliegt,
    entscheidet spaeter der Composition Root. Hier steht nur der WUNSCH.
    """

    ANONYMOUS = "anonymous"
    APP_RESOLVED = "app_resolved"


class RecordingState(StrEnum):
    """Lebenszyklus-Zustand einer Aufzeichnung (exakt wie ``TaskState``).

    ``CREATED`` (angelegt, laeuft noch nicht) -> ``ACTIVE`` (zeichnet auf) <->
    ``PAUSED`` (ausgesetzt) -> ``FINISHED`` (endgueltig beendet). Die erlaubten
    Uebergaenge sind in den Uebergangs-Funktionen unten kodiert.
    """

    CREATED = "created"
    ACTIVE = "active"
    PAUSED = "paused"
    FINISHED = "finished"


class InvalidRecordingTransition(Exception):
    """Ein angeforderter Zustandsuebergang ist vom aktuellen ``state`` aus unzulaessig.

    EIGENSTAENDIG (erbt von ``Exception``, NICHT von ``ValueError`` -- analog
    ``InvalidTaskTransition``): der Aufrufer kann genau diesen Fehler fangen, ohne einen
    unrelated ``ValueError`` mitzunehmen. Traegt den versuchten Uebergang
    (``state`` -> ``transition``) im Bezug, damit der Fehler ohne Kontext-Rekonstruktion
    sprechend ist.
    """

    def __init__(self, transition: str, state: "RecordingState") -> None:
        super().__init__(f"Unzulaessiger Uebergang {transition!r} aus Zustand {state.value!r}")
        self.transition = transition
        self.state = state


@dataclass(frozen=True)
class OutboundRecording:
    """Eine vom Nutzer gestartete Aussenkontakte-Aufzeichnung (Datentraeger + Identitaet).

    ``id`` ist die Aufzeichnungs-Identitaet, ``label``/``purpose`` die benutzerseitige
    Beschreibung. ``mode``/``depth`` klassifizieren WIE abgelegt und mit welcher
    gewuenschten Rechte-Tiefe; ``state`` haelt den Lebenszyklus, ``interval_s`` das
    Mess-Intervall. Die Zeitfelder sind Unix-ts (``float``).

    ``max_duration_s`` ist NUR fuer ``DETAIL`` relevant (Obergrenze des Fensters ab
    ``effective_start``); bei ``AGGREGATE`` bleibt es ``None`` (kein Zeitlimit). Die
    Domaene rechnet nur mit diesen Werten -- sie fuellt sie NICHT (kein ``time.time()``).

    ``effective_start``/``max_duration_s`` stehen ans Ende mit Defaults: so bleibt die
    positionsbasierte Konstruktion zukunftssicher (Hausmuster).
    """

    id: str
    label: str
    purpose: str
    mode: RecordingMode
    depth: DetailDepth
    state: RecordingState
    interval_s: int
    created_at: float
    # Effektiver Start (absoluter Unix-ts), gesetzt beim ERSTEN Uebergang nach ACTIVE.
    # Bleibt ueber Pausen UNVERAENDERT und wird bei FINISHED wieder geleert (``None``).
    # Bezugs-ts des DETAIL-Fensters. Default ``None``, ans Ende einsortiert.
    effective_start: float | None = None
    # Maximaldauer des DETAIL-Fensters in Sekunden ab ``effective_start``. Bei
    # AGGREGATE ``None`` (kein Limit). Default ``None`` -- der Use-Case setzt spaeter
    # einen Default; ans Ende einsortiert wie ``effective_start``.
    max_duration_s: int | None = None

    def __post_init__(self) -> None:
        """Prueft genau zwei Invarianten und wirft ``ValueError`` bei Verletzung.

        (a) ``interval_s`` muss in ``ALLOWED_INTERVALS`` liegen.
        (b) Ist ``mode`` ``DETAIL`` UND ``max_duration_s`` gesetzt, muss
            ``1 <= max_duration_s <= MAX_DETAIL_DURATION_S`` gelten (24-h-Deckel hart in
            der Domaene). ``max_duration_s`` ``None`` ist erlaubt (Default spaeter).

        Modusfremde Kombinationen (z. B. AGGREGATE mit gesetztem ``max_duration_s``)
        werden hier bewusst NICHT hart erzwungen -- nur diese zwei Invarianten.
        """
        if self.interval_s not in ALLOWED_INTERVALS:
            raise ValueError(
                f"interval_s {self.interval_s!r} nicht erlaubt -- zulaessig: {ALLOWED_INTERVALS}"
            )
        if (
            self.mode is RecordingMode.DETAIL
            and self.max_duration_s is not None
            and not 1 <= self.max_duration_s <= MAX_DETAIL_DURATION_S
        ):
            raise ValueError(
                f"max_duration_s {self.max_duration_s!r} ausserhalb "
                f"[1, {MAX_DETAIL_DURATION_S}] (DETAIL-Deckel)"
            )


def is_recording_active(rec: OutboundRecording, now: float) -> bool:
    """Praedikat: zeichnet ``rec`` zum Zeitpunkt ``now`` aktiv auf?

    Reine Zeitrechnung -- die Domaene haelt KEINE Uhr, ``now`` kommt vom Use-Case.

    * ``state`` nicht ``ACTIVE`` -> ``False``.
    * ``AGGREGATE``: solange ``ACTIVE`` -> ``True`` (kein Zeitfenster).
    * ``DETAIL``: ``effective_start`` UND ``max_duration_s`` gesetzt UND
      ``effective_start <= now < effective_start + max_duration_s`` -> ``True``; fehlt
      eines davon oder liegt ``now`` ausserhalb -> ``False`` (kein stiller Fallback).
    """
    if rec.state is not RecordingState.ACTIVE:
        return False
    if rec.mode is RecordingMode.AGGREGATE:
        return True
    if rec.effective_start is None or rec.max_duration_s is None:
        return False
    return rec.effective_start <= now < rec.effective_start + rec.max_duration_s


def start(rec: OutboundRecording, effective_start: float) -> OutboundRecording:
    """Uebergang ``CREATED`` -> ``ACTIVE``; setzt den effektiven Start.

    Der ``effective_start`` wird NUR gesetzt, wenn er noch ``None`` ist (erster Start --
    ADR-0033-Muster): ein bereits gesetzter Wert bliebe unveraendert. Aus ``CREATED``
    heraus ist er immer ``None``, der Guard ist also vor allem Aussage ueber die
    Invariante. Jeder andere Ausgangszustand wirft.
    """
    if rec.state is not RecordingState.CREATED:
        raise InvalidRecordingTransition("start", rec.state)
    new_effective_start = (
        rec.effective_start if rec.effective_start is not None else effective_start
    )
    return dataclasses.replace(
        rec, state=RecordingState.ACTIVE, effective_start=new_effective_start
    )


def pause(rec: OutboundRecording) -> OutboundRecording:
    """Uebergang ``ACTIVE`` -> ``PAUSED``. Jeder andere Ausgangszustand wirft."""
    if rec.state is not RecordingState.ACTIVE:
        raise InvalidRecordingTransition("pause", rec.state)
    return dataclasses.replace(rec, state=RecordingState.PAUSED)


def resume(rec: OutboundRecording) -> OutboundRecording:
    """Uebergang ``PAUSED`` -> ``ACTIVE``. Jeder andere Ausgangszustand wirft.

    Setzt ``effective_start`` NICHT neu: Fortsetzen aus einer Pause behaelt den
    urspruenglichen effektiven Start -- die DETAIL-Maximaldauer ist reine Wanduhr ab dem
    ersten Start, die Pausenzeit zaehlt MIT.
    """
    if rec.state is not RecordingState.PAUSED:
        raise InvalidRecordingTransition("resume", rec.state)
    return dataclasses.replace(rec, state=RecordingState.ACTIVE)


def stop(rec: OutboundRecording) -> OutboundRecording:
    """Uebergang ``{ACTIVE, PAUSED}`` -> ``FINISHED``; leert den effektiven Start.

    Setzt ``effective_start`` zurueck auf ``None``: die Aufzeichnung ist beendet, ein
    kuenftiger erneuter Start wuerde einen FRISCHEN effektiven Start setzen. Jeder andere
    Ausgangszustand als ``ACTIVE``/``PAUSED`` wirft.
    """
    if rec.state not in (RecordingState.ACTIVE, RecordingState.PAUSED):
        raise InvalidRecordingTransition("stop", rec.state)
    return dataclasses.replace(rec, state=RecordingState.FINISHED, effective_start=None)


@dataclass(frozen=True)
class ContactDelta:
    """Ein einzelner beobachteter Kontakt-Beitrag zu einer Remote-IP (Datentraeger).

    Die roh beobachteten Werte EINES Mess-Zyklus zu einer Gegenstelle, die der
    AGGREGATE-Schreibpfad in einen ``AggregatedContact`` einrechnet. Die
    Anreicherungsfelder (``hostname``/``country``/``operator``/``asn``/``app_name`` und
    ``remote_port``) sind ``None``, wenn fuer diesen Zyklus nicht ermittelbar.
    ``connection_count`` ist die in diesem Zyklus gezaehlte Anzahl Verbindungen.
    """

    remote_ip: str
    remote_port: int | None
    hostname: str | None
    country: str | None
    operator: str | None
    asn: str | None
    app_name: str | None
    connection_count: int


@dataclass(frozen=True)
class AggregatedContact:
    """Der fortlaufend verdichtete Datensatz EINER Remote-IP (Datentraeger).

    ``first_seen``/``last_seen`` sind Unix-ts (erster bzw. letzter Kontakt),
    ``total_count`` die aufsummierte Verbindungsanzahl, ``peak_count`` das Maximum eines
    einzelnen Zyklus. Die Anreicherungsfelder spiegeln den jeweils zuletzt bekannten
    nicht-leeren Wert (s. ``merge_contact``).
    """

    remote_ip: str
    first_seen: float
    last_seen: float
    total_count: int
    peak_count: int
    remote_port: int | None
    hostname: str | None
    country: str | None
    operator: str | None
    asn: str | None
    app_name: str | None


def _delta_or_keep[T](delta_value: T | None, existing_value: T | None) -> T | None:
    """``delta_value`` uebernehmen, wenn nicht ``None``, sonst ``existing_value`` bewahren.

    Optional-Variante des ``_scan_or_keep``-Musters aus ``domain/devices.py``: ein
    Mess-Zyklus, der ein Anreicherungsfeld nicht ermitteln konnte (``None``), soll einen
    frueher ermittelten Wert NICHT loeschen.
    """
    return delta_value if delta_value is not None else existing_value


def merge_contact(
    existing: AggregatedContact | None, delta: ContactDelta, now: float
) -> AggregatedContact:
    """Upsert-Merge-Regel des AGGREGATE-Schreibpfads als reine Funktion.

    - ``existing`` ``None`` -> Neuanlage: ``first_seen = last_seen = now``,
      ``total_count = peak_count = delta.connection_count``, uebrige Felder aus ``delta``.
    - ``existing`` vorhanden -> ``last_seen = now``,
      ``total_count += delta.connection_count``,
      ``peak_count = max(alt, delta.connection_count)``, ``first_seen`` BLEIBT. Die
      Anreicherungsfelder (``remote_port``/``hostname``/``country``/``operator``/``asn``/
      ``app_name``) werden nur uebernommen, wenn der ``delta``-Wert nicht ``None`` ist
      (sonst Alt-Wert bewahren, s. ``_delta_or_keep``). ``remote_ip`` bleibt.

    Reine Funktion: ``now`` kommt vom Use-Case (die Domaene haelt keine Uhr).
    """
    if existing is None:
        return AggregatedContact(
            remote_ip=delta.remote_ip,
            first_seen=now,
            last_seen=now,
            total_count=delta.connection_count,
            peak_count=delta.connection_count,
            remote_port=delta.remote_port,
            hostname=delta.hostname,
            country=delta.country,
            operator=delta.operator,
            asn=delta.asn,
            app_name=delta.app_name,
        )
    return AggregatedContact(
        remote_ip=existing.remote_ip,
        first_seen=existing.first_seen,
        last_seen=now,
        total_count=existing.total_count + delta.connection_count,
        peak_count=max(existing.peak_count, delta.connection_count),
        remote_port=_delta_or_keep(delta.remote_port, existing.remote_port),
        hostname=_delta_or_keep(delta.hostname, existing.hostname),
        country=_delta_or_keep(delta.country, existing.country),
        operator=_delta_or_keep(delta.operator, existing.operator),
        asn=_delta_or_keep(delta.asn, existing.asn),
        app_name=_delta_or_keep(delta.app_name, existing.app_name),
    )
