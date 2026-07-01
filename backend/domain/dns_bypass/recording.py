"""Aufzeichnung des netzweiten DNS-Umgehungs-Waechters -- reine, zeitfreie Logik.

Eine vom Nutzer gestartete, BENANNTE Aufzeichnung, WELCHE Geraete des Netzes ueber die
Zeit an nicht-erwartete Resolver DNS-Anfragen stellen. Strukturgleich zur Aufzeichnungs-
Logik der outbound_log-Domaene (``domain/outbound_log.py``), aber bewusst EIGENSTAENDIG:
KEIN Import aus ``domain.outbound_log`` oder einer anderen Domaene (independence-Contract).
Die Datei definiert nur, WAS eine DNS-Umgehungs-Aufzeichnung ist und die reinen
Zustands-Regeln darueber -- sie kennt KEINE Persistenz, KEINEN Loop, KEINE Uhr: jede
zeitabhaengige Frage bekommt ``now``/``effective_start`` als Parameter (kein
``time.time()`` in der Domaene -- ADR 0002, stdlib only, framework-frei).

Muster konsequent aus dem Vorbild uebernommen: frozen dataclasses + StrEnum,
eigenstaendiger Domaenen-Fehler (``InvalidDnsBypassRecordingTransition`` erbt von
``Exception``, NICHT von ``ValueError`` -- analog ``InvalidRecordingTransition``),
Zustandsuebergaenge als reine Funktionen, die via ``dataclasses.replace`` ein NEUES Objekt
zurueckgeben (kein In-Place-Mutieren auf einer frozen dataclass). ``float``-Zeitstempel
sind Unix-ts.

BEWUSSTE REDUKTION gegenueber outbound_log (die DNS-Domaene ist anders): KEINE Achsen
``mode``/``depth``/``interval_s``/``max_duration_s`` (Snapshot-Intervall, App-Tiefe -- beim
netzweiten DNS-Sniff sinnlos): der DNS-Waechter zeichnet IMMER Detail UND Aggregat
gleichzeitig auf, ohne Modus-Wahl. Der Lebenszyklus ist schlank ``CREATED -> ACTIVE ->
FINISHED`` (kein ``PAUSED`` -- eine DNS-Aufzeichnung wird gestartet und gestoppt).
"""

import dataclasses
from dataclasses import dataclass
from enum import StrEnum

# Deckel fuer die Beleg-qname-Stichprobe eines Aggregats. Bewusst schlank (fuenf reichen
# als Beleg, was ein Geraet gegen einen nicht-erwarteten Resolver gefragt hat) -- Muster
# der ``sample_qnames``-Grenze in ``domain.dns_bypass.models.DnsBypassFinding``.
MAX_SAMPLE_QNAMES = 5


class DnsBypassRecordingState(StrEnum):
    """Lebenszyklus-Zustand einer DNS-Umgehungs-Aufzeichnung.

    ``CREATED`` (angelegt, laeuft noch nicht) -> ``ACTIVE`` (zeichnet auf) ->
    ``FINISHED`` (endgueltig beendet). BEWUSST schlank -- kein ``PAUSED`` (eine
    DNS-Aufzeichnung wird gestartet und gestoppt, nicht ausgesetzt). Die erlaubten
    Uebergaenge sind in den Uebergangs-Funktionen unten kodiert.
    """

    CREATED = "created"
    ACTIVE = "active"
    FINISHED = "finished"


class InvalidDnsBypassRecordingTransition(Exception):
    """Ein angeforderter Zustandsuebergang ist vom aktuellen ``state`` aus unzulaessig.

    EIGENSTAENDIG (erbt von ``Exception``, NICHT von ``ValueError`` -- analog
    ``InvalidRecordingTransition``): der Aufrufer kann genau diesen Fehler fangen, ohne
    einen unrelated ``ValueError`` mitzunehmen. Traegt den versuchten Uebergang
    (``state`` -> ``transition``) im Bezug, damit der Fehler ohne Kontext-Rekonstruktion
    sprechend ist.
    """

    def __init__(self, transition: str, state: "DnsBypassRecordingState") -> None:
        super().__init__(f"Unzulaessiger Uebergang {transition!r} aus Zustand {state.value!r}")
        self.transition = transition
        self.state = state


@dataclass(frozen=True)
class DnsBypassRecording:
    """Eine vom Nutzer gestartete DNS-Umgehungs-Aufzeichnung (Datentraeger + Identitaet).

    ``id`` ist die Aufzeichnungs-Identitaet, ``label``/``purpose`` die benutzerseitige
    Beschreibung. ``state`` haelt den Lebenszyklus; die Zeitfelder sind Unix-ts (``float``).

    ``interface`` ist die Netz-Schnittstelle, auf der gesnifft wird (``None``, wenn nicht
    festgelegt). ``expected_servers`` ist die MOMENTAUFNAHME der erwarteten Resolver-Menge
    zum Startzeitpunkt -- als ehrlicher Beleg, gegen welche Menge die spaeteren Umgehungen
    klassifiziert wurden (die Menge kann sich danach aendern, der Beleg friert sie fest).

    ``effective_start``/``interface``/``expected_servers`` stehen ans Ende mit Defaults: so
    bleibt die positionsbasierte Konstruktion zukunftssicher (Hausmuster).
    """

    id: str
    label: str
    purpose: str
    state: DnsBypassRecordingState
    created_at: float
    # Effektiver Start (absoluter Unix-ts), gesetzt beim Uebergang nach ACTIVE. Wird bei
    # FINISHED wieder geleert (``None``). Default ``None``, ans Ende einsortiert.
    effective_start: float | None = None
    # Netz-Schnittstelle des Sniffs (``None``, wenn nicht festgelegt).
    interface: str | None = None
    # Momentaufnahme der erwarteten Resolver-Menge zum Startzeitpunkt (ehrlicher Beleg).
    expected_servers: tuple[str, ...] = ()


def start(
    rec: DnsBypassRecording,
    effective_start: float,
    expected_servers: tuple[str, ...],
) -> DnsBypassRecording:
    """Uebergang ``CREATED`` -> ``ACTIVE``; setzt Start und den erwarteten-Menge-Beleg.

    Der ``effective_start`` wird NUR gesetzt, wenn er noch ``None`` ist (Muster
    ``outbound_log.start``): aus ``CREATED`` heraus ist er immer ``None``, der Guard ist
    also vor allem Aussage ueber die Invariante. Gleichzeitig friert ``start`` die zum
    Startzeitpunkt erwartete Resolver-Menge als ``expected_servers`` ein (ehrlicher Beleg).
    Jeder andere Ausgangszustand als ``CREATED`` wirft.
    """
    if rec.state is not DnsBypassRecordingState.CREATED:
        raise InvalidDnsBypassRecordingTransition("start", rec.state)
    new_effective_start = (
        rec.effective_start if rec.effective_start is not None else effective_start
    )
    return dataclasses.replace(
        rec,
        state=DnsBypassRecordingState.ACTIVE,
        effective_start=new_effective_start,
        expected_servers=expected_servers,
    )


def stop(rec: DnsBypassRecording) -> DnsBypassRecording:
    """Uebergang ``ACTIVE`` -> ``FINISHED``; leert den effektiven Start.

    Setzt ``effective_start`` zurueck auf ``None``: die Aufzeichnung ist beendet (Muster
    ``outbound_log.stop``). ``expected_servers`` BLEIBT als eingefrorener Beleg erhalten.
    Jeder andere Ausgangszustand als ``ACTIVE`` wirft.
    """
    if rec.state is not DnsBypassRecordingState.ACTIVE:
        raise InvalidDnsBypassRecordingTransition("stop", rec.state)
    return dataclasses.replace(rec, state=DnsBypassRecordingState.FINISHED, effective_start=None)


def edit(rec: DnsBypassRecording, label: str, purpose: str) -> DnsBypassRecording:
    """Aendert die DEFINITION einer Aufzeichnung -- reine Funktion, kein Zeitbezug.

    Fachregel (WAS, fest entschieden): ``label``/``purpose`` sind in JEDEM Zustand
    aenderbar (Muster ``outbound_log.edit`` fuer die label/purpose-Achse). Die DNS-Domaene
    hat KEINE modusartigen Konfig-Felder, die zu sperren waeren -- deshalb kein
    ``ConfigLocked``-Pfad. Zeitfelder (``created_at``/``effective_start``),
    ``state``, ``interface`` und ``expected_servers`` bleiben unberuehrt.
    """
    return dataclasses.replace(rec, label=label, purpose=purpose)


@dataclass(frozen=True)
class DnsBypassDetailRow:
    """Eine einzelne Zeile des rohen DETAIL-Zeitverlaufs (Lese-Datentraeger).

    Der benannte Lese-Record des DETAIL-Append-Stores: EINE beobachtete DNS-Umgehungs-
    Anfrage zu einem Zeitstempel, wie sie der DETAIL-Adapter beim ``range`` herausgibt.
    Muster ``OutboundDetailRow`` -- ein Lese-Record mit mehreren Feldern wird benannt (kein
    Tuple) und lebt in ``domain/``, NICHT im ports-Ring.

    ``ts`` ist Unix-ts. ``src_ip`` ist das fragende Geraet, ``dst_ip`` der nicht-erwartete
    Resolver, ``l4`` ist ``"udp"``/``"tcp"``, ``qname`` der abgefragte Name (``""``
    moeglich -- der Sniffer liefert ihn best-effort).
    """

    ts: float
    src_ip: str
    dst_ip: str
    l4: str
    qname: str


@dataclass(frozen=True)
class BypassDelta:
    """Ein einzelner beobachteter Umgehungs-Beitrag zu einer (Geraet, Resolver)-Gruppe.

    Der roh beobachtete Beitrag EINES Schreib-Zyklus zu einer (``src_ip``, ``dst_ip``)-
    Gruppe, den der AGGREGATE-Schreibpfad in ein ``AggregatedBypass`` einrechnet (Muster
    ``ContactDelta``). ``qname`` ist der zuletzt beobachtete abgefragte Name (``""``
    moeglich); ``count`` ist die in diesem Zyklus gezaehlte Anzahl Anfragen.
    """

    src_ip: str
    dst_ip: str
    qname: str
    count: int


@dataclass(frozen=True)
class AggregatedBypass:
    """Der fortlaufend verdichtete Datensatz EINER (Geraet, Resolver)-Gruppe.

    ``first_seen``/``last_seen`` sind Unix-ts (erste bzw. letzte Umgehung dieser Gruppe),
    ``query_count`` die aufsummierte Anzahl Anfragen. ``sample_qnames`` sind bis zu
    ``MAX_SAMPLE_QNAMES`` distinct nicht-leere qnames als Beleg, deterministisch in
    Erst-Vorkommen-Reihenfolge (Muster ``sample_qnames`` in ``DnsBypassFinding``).
    """

    src_ip: str
    dst_ip: str
    first_seen: float
    last_seen: float
    query_count: int
    sample_qnames: tuple[str, ...]


def _merge_sample_qnames(existing: tuple[str, ...], qname: str) -> tuple[str, ...]:
    """Fuegt ``qname`` distinct in die Beleg-Stichprobe ein (Deckel ``MAX_SAMPLE_QNAMES``).

    Reine Funktion: leere qnames (``""``) und bereits enthaltene werden ignoriert, ist der
    Deckel erreicht bleibt die Stichprobe unveraendert. Erst-Vorkommen-Reihenfolge bleibt
    stabil (deterministischer Beleg).
    """
    if qname == "" or qname in existing or len(existing) >= MAX_SAMPLE_QNAMES:
        return existing
    return (*existing, qname)


def merge_bypass(
    existing: AggregatedBypass | None, delta: BypassDelta, now: float
) -> AggregatedBypass:
    """Upsert-Merge-Regel des AGGREGATE-Schreibpfads als reine Funktion.

    - ``existing`` ``None`` -> Neuanlage: ``first_seen = last_seen = now``,
      ``query_count = delta.count``, ``sample_qnames`` aus dem einen ``delta.qname`` (leer
      -> leere Stichprobe). ``src_ip``/``dst_ip`` aus ``delta``.
    - ``existing`` vorhanden -> ``last_seen = now``, ``query_count += delta.count``,
      ``first_seen`` BLEIBT, ``sample_qnames`` um ``delta.qname`` distinct erweitert (bis
      Deckel ``MAX_SAMPLE_QNAMES``). ``src_ip``/``dst_ip`` bleiben.

    Reine Funktion: ``now`` kommt vom Use-Case (die Domaene haelt keine Uhr).
    """
    if existing is None:
        return AggregatedBypass(
            src_ip=delta.src_ip,
            dst_ip=delta.dst_ip,
            first_seen=now,
            last_seen=now,
            query_count=delta.count,
            sample_qnames=_merge_sample_qnames((), delta.qname),
        )
    return AggregatedBypass(
        src_ip=existing.src_ip,
        dst_ip=existing.dst_ip,
        first_seen=existing.first_seen,
        last_seen=now,
        query_count=existing.query_count + delta.count,
        sample_qnames=_merge_sample_qnames(existing.sample_qnames, delta.qname),
    )
