"""Ports der monitoring-Domaene: Vertraege fuer den Live-Connectivity-Loop (M.5).

Sechs Vertraege, gruppiert nach Loop-Belang:

* **Messung** -- ``MonitorPingerPort`` (pingt ein Target -> PingSample).
* **Konsequenzen** -- ``MonitorNotifierPort`` (Notification), ``MonitorBroadcasterPort``
  (Live-Update an die Subscriber), ``AlertRaiserPort`` (regelbasierter Alert, A.7a --
  alerting-Naht ueber app.py, der Port nennt nichts aus alerting).
* **Persistenz** -- ``RttHistoryRepository`` (rtt_history), ``MonitorEventRepository``
  (monitor_events).
* **Konfiguration** -- ``MonitorTargetSource`` (welche Targets ueberwachen?).

SCOPE (M.3): die Loop-Ports; ``ScheduleRepository``/``ScanJobScheduler`` kamen mit
M.6, ``SlaSampleRepository`` kommt mit M.7. Die metrics-Vertraege folgen mit M.8 --
ein Port ohne seinen Adapter+Use-Case waere ein toter Vertrag mit Signatur, die sich
erst beim Adapter-Bau zeigt. Jeder GEZOGENE Port ist
dagegen als vollstaendige kohaerente Einheit definiert (Repos: save UND recent),
nicht nach Nutzungsphase zerschnitten -- Muster wie ``ScanHistoryRepository`` /
``DeviceRepository``.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning). Die Vertragspruefung laeuft statisch ueber mypy und ueber die
Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

I/O-/Seiteneffekt-Methoden sind ``async`` (Ping, Notify, Broadcast -- subprocess
bzw. Transport, der Adapter kapselt Blockierendes ueber ``run_in_executor``). Die
Persistenz-Repos sind ``sync`` (Muster scanning/devices: sqlite ist schnell genug,
kein executor); ebenso ``MonitorTargetSource.load`` (Komposition aus settings +
interfaces, kein Netz-I/O des Loops).

``ports/`` kennt NUR ``domain/monitoring``-Typen + stdlib. KEIN ``modules/``- und
kein ``infrastructure/``-Import -- import-linter-Contract "ports kennen hoechstens
domain". Import von ``domain`` ist erlaubt (nur die Gegenrichtung ist verboten).
"""

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from domain.monitoring import (
    LoggingEventRow,
    LoggingRttSample,
    LoggingTask,
    MonitorEvent,
    MonitorEventType,
    MonitorTarget,
    PingSample,
    SlaSample,
)

# Der Callback, den der ScanJobScheduler bei Faelligkeit eines Schedules ruft.
# Signatur exakt wie die Altcode-``_register_job``-kwargs (cidr, profile_id,
# schedule_id) bzw. ``app._scheduled_scan``. Der Job-Engine-Port kennt scanning
# NICHT -- er ruft nur diesen generischen Callable; die Verdrahtung an den
# scanning-Use-Case macht der Composition Root (``app.py``, M.9).
type ScanTriggerCallback = Callable[[str, str, int], Awaitable[None]]

# ── Messung ───────────────────────────────────────────────────────────────


class MonitorPingerPort(Protocol):
    """Misst die Erreichbarkeit eines Targets per Ping-Burst."""

    async def ping(self, target: MonitorTarget) -> PingSample:
        """Pingt ``target`` (Altcode: 3er-Burst) und aggregiert zu ``PingSample``.

        Blockierendes ``ping``-Subprocess im Altcode (``_ping_burst``); der Adapter
        (M.4) kapselt das ueber ``run_in_executor``, die Methode bleibt ``async``.
        ``target.host``/``target.interface`` steuern Ziel und Interface-Bindung.
        Ein nicht erreichbares Target ist KEIN Fehler -- es kommt als
        ``PingSample(alive=False, rtt_ms=-1.0, loss_pct=...)`` zurueck (der
        RTT-Sentinel ``-1.0`` bleibt erhalten, wie in ``domain.PingSample``).
        """
        ...


# ── Konsequenzen ──────────────────────────────────────────────────────────


class MonitorNotifierPort(Protocol):
    """Benachrichtigt ueber einen erkannten Uebergang (Desktop-Notification).

    Die Naht aus M.2: ``classify_transition`` bestimmt das Event, ``should_notify``
    entscheidet OB benachrichtigt wird -- erst dann ruft der Loop diesen Port. So
    kennt weder Domaene noch Loop das ``osascript``/``subprocess`` des Altcodes
    (``_notify_macos``); das lebt allein im Adapter.
    """

    async def notify(self, event: MonitorEvent) -> None:
        """Loest eine Notification fuer ``event`` aus.

        Best-effort: ein fehlgeschlagener Notification-Versuch ist KEIN Loop-Fehler
        (der Adapter faengt/loggt). Auf Plattformen ohne Notification-Backend
        (Linux: der Altcode-``osascript``-Pfad ist macOS-only) ist die Methode ein
        no-op -- vertraglich erlaubt, kein Fehler.
        """
        ...


class MonitorBroadcasterPort(Protocol):
    """Veroeffentlicht ein Live-Update an die aktuell verbundenen Subscriber.

    Der monitor-Loop ist ein ENDLOSER zentraler Loop, der an N WS-Subscriber
    PUSHT (Fan-out) -- anders als der scanning-Use-Case (1 endlicher Generator <->
    1 WS-Handler). Darum ein ECHTER Broadcaster-Port statt eines yieldenden
    Generators: der Loop sagt "hier ist ein Update", ohne zu wissen, dass dahinter
    N WS-Connections haengen. Subscriber-Verwaltung (subscribe/unsubscribe) und das
    eigentliche Fan-out leben im Adapter (M.9-nah).

    WICHTIG zur Naht: Die Methode nimmt DOMAENEN-Objekte, KEIN fertiges WS-dict.
    Der Adapter baut daraus das ``monitor_update``-Frame (inkl. der ``%H:%M:%S``-
    Zeitformatierung -- die Format-Divergenz-Naht aus M.2 bleibt am Rand, nicht im
    Loop).
    """

    async def broadcast(
        self,
        target: MonitorTarget,
        sample: PingSample,
        event: MonitorEventType | None,
    ) -> None:
        """Veroeffentlicht die Messung ``sample`` fuer ``target`` mit ``event``.

        ``target`` liefert ``id``/``label`` fuer das Frame, ``sample`` die Messwerte
        (alive/rtt_ms/loss_pct/timestamp), ``event`` den erkannten Uebergang oder
        ``None`` (kein Uebergang -- das Frame traegt dann ``event: null``, wie im
        Altcode). Keine Subscriber -> die Methode tut nichts (kein Fehler).
        """
        ...


class MonitorLoggingSinkPort(Protocol):
    """Hoert den Live-Loop fuer das opt-in Langzeit-Logging mit (B-II, Schreibpfad).

    Die DRITTE best-effort-Konsequenz des Loops neben ``MonitorNotifierPort`` und
    ``AlertRaiserPort`` -- aber an EINER anderen Naht: nicht an der should_notify-Flanke,
    sondern PRO Tick je gemessenem Target (der Sink entscheidet selbst, ob eine aktive
    Logging-Aufgabe an diesem Target zu bedienen ist). Der Loop reicht nur seine rohen
    Messdaten durch und bleibt logging-blind: WELCHE Aufgaben aktiv sind und WAS sie
    gemaess ``capture_mode`` schreiben, weiss allein der Adapter (er haelt die drei
    Logging-Repos). So nennt dieser Port -- und damit ``ports/monitoring`` -- NICHTS
    aus dem Logging-Kern ueber die Domaenen-Typen hinaus, die der Loop ohnehin fuehrt.

    BEST-EFFORT-Vertrag, EXAKT wie ``MonitorNotifierPort.notify`` / ``AlertRaiserPort``:
    ``record`` wirft NIE (der Adapter faengt+loggt jeden Persistenz-Fehler selbst). Der
    Live-Monitor (rtt_history/monitor_events/Notify/Broadcast) darf NIEMALS wegen eines
    Logging-Fehlers sterben -- darum braucht der Loop kein try/except um diesen Aufruf,
    genau wie bei den beiden anderen Konsequenz-Ports.
    """

    async def record(
        self,
        target: MonitorTarget,
        sample: PingSample,
        event: MonitorEventType | None,
        now: float,
    ) -> None:
        """Persistiert die Messung ``sample`` fuer ``target`` in alle aktiven Aufgaben.

        ``target`` liefert die Ziel-Identitaet (``id`` filtert die zustaendigen
        Aufgaben), ``sample`` die Messwerte (rtt_ms/loss_pct/alive), ``event`` den
        erkannten Uebergang oder ``None`` (keine Flanke), ``now`` den Bezugs-ts (der
        bereits gemessene ``sample.timestamp`` -- KEINE neue Uhr im Loop). Der Adapter
        waehlt die aktiven Aufgaben am Ziel (state ACTIVE + Zeitfenster offen) und
        schreibt je nach ``capture_mode`` die dichten RTT-Punkte und/oder die Flanke.
        Keine passende Aufgabe -> no-op (kein Fehler). Best-effort -- wirft NIE.
        """
        ...


class AlertRaiserPort(Protocol):
    """Loest einen Alert fuer einen erkannten Uebergang aus (alerting-Naht, A.7a).

    Die ZWEITE Konsequenz neben ``MonitorNotifierPort``: erst ``classify_transition``
    bestimmt das Event, ``should_notify`` entscheidet OB -- bei ``True`` ruft der Loop
    sowohl ``notify`` (Desktop-Notification) als auch diesen Port (regelbasierter
    Alert: alert_history-Write + E-Mail/macos je Nutzer-Regel). Der Loop reicht nur
    sein eigenes ``MonitorEvent`` durch und bleibt alerting-blind: das Mapping
    ``MonitorEvent`` -> ``RaiseAlert(rule_type/target/message)`` lebt im Composition
    Root (``app.py``, ``_MonitorAlertRaiser``), NICHT hier -- so nennt dieser Port
    (und damit ``ports/monitoring``) NICHTS aus der alerting-Domaene (independence,
    CI-hart). Symmetrisch zur ``MonitorNotifierPort``-Naht (M.2/M.3): die Domaene
    kennt weder das ``osascript`` des Notifiers noch die ``alert_rules``-Auswahl des
    Raisers.
    """

    async def raise_alert(self, event: MonitorEvent) -> None:
        """Loest fuer ``event`` die passenden Alert-Regeln aus.

        Best-effort -- EXAKT wie ``MonitorNotifierPort.notify``: wirft NIE. Der
        Adapter faengt+loggt jeden Fehler selbst; ein fehlgeschlagener Alert ist KEIN
        Loop-Fehler und darf weder den ``tick`` killen noch die ``notify``-Konsequenz
        verschlucken (beide Konsequenzen sind dadurch gegenseitig isoliert, ohne dass
        der Use-Case ein try/except braucht). Matcht keine Regel -> no-op (kein
        Fehler), wie der vom Port vorgesehene Ruhezustand.
        """
        ...


# ── Persistenz ────────────────────────────────────────────────────────────


class RttHistoryRepository(Protocol):
    """Persistenz der RTT-Verlaufsdaten (Altcode-Tabelle ``rtt_history``)."""

    def save(self, sample: PingSample) -> None:
        """Legt einen RTT-Messpunkt aus ``sample`` ab.

        Der Altcode trimmt pro Target auf die letzten 1000 Samples -- das ist
        Adapter-Mechanik (M.4), kein Teil des Vertrags. Nimmt das fertige
        Domaenen-``PingSample`` (``target_id`` darin identifiziert das Target).
        """
        ...

    def recent(self, target_id: str, limit: int) -> list[PingSample]:
        """Letzte RTT-Messpunkte eines Targets, chronologisch, auf ``limit`` begrenzt.

        Speist den REST-Endpunkt ``/api/monitor/rtt/{id}`` (M.9). Unbekanntes
        Target / keine Daten -> ``[]``, niemals ``None``. Reihenfolge wie Altcode
        ``get_rtt_history`` (aelteste zuerst).
        """
        ...


class MonitorEventRepository(Protocol):
    """Persistenz der Uebergangs-Ereignisse (Altcode-Tabelle ``monitor_events``)."""

    def save(self, event: MonitorEvent) -> None:
        """Legt ein erkanntes Uebergangs-Ereignis ab.

        Nimmt das fertige Domaenen-``MonitorEvent`` (``event.event`` ist der
        ``MonitorEventType``). Die ``datetime``-Spalten-Formatierung
        (``%Y-%m-%d %H:%M:%S``) ist Adapter-Sache (M.4) -- das Domaenen-Objekt
        haelt nur den rohen ``timestamp``.
        """
        ...

    def recent(self, limit: int) -> list[MonitorEvent]:
        """Letzte Ereignisse ueber ALLE Targets, neueste zuerst, auf ``limit`` begrenzt.

        Speist den REST-Endpunkt ``/api/monitor/events`` (M.9). Keine Ereignisse ->
        ``[]``, niemals ``None``. Reihenfolge wie Altcode ``get_monitor_events``
        (``ts`` absteigend).
        """
        ...


# ── Konfiguration ─────────────────────────────────────────────────────────


class MonitorTargetSource(Protocol):
    """Liefert die aktuell zu ueberwachenden Targets.

    Kapselt die heterogene Komposition des Altcodes (``_build_monitor_targets``):
    Interface-Gateways (Hilfsmodul ``interfaces``), die fest verdrahteten
    Internet-Targets (8.8.8.8 / 1.1.1.1) und die benutzerdefinierten Targets aus
    den Settings (``monitor_custom_targets``). Aus Loop-Sicht ist das EINE
    Verantwortung -- "die Targets" --, die drei Herkuenfte sind Adapter-Sache (M.4).
    """

    def load(self) -> list[MonitorTarget]:
        """Aktuelle Target-Liste, frisch zusammengesetzt.

        Bei jedem Aufruf neu gelesen -- so traegt der Altcode-Live-Reload (ein
        ueber ``/api/monitor/targets`` geaendertes Custom-Target wirkt beim
        naechsten ``load``). Keine Targets konfiguriert -> die fest verdrahteten
        Internet-Targets bleiben; die Liste ist im Normalfall nie leer.
        """
        ...


# ── Scheduler (M.6) ───────────────────────────────────────────────────────
# Zwei getrennte Belange des Altcode-``modules/scheduler.py``: die reine
# ``scan_schedules``-Persistenz (``ScheduleRepository``) und die APScheduler-Job-
# Engine (``ScanJobScheduler``). Die Altcode-Kopplung (``add_schedule`` ruft
# ``_register_job``) wird entkoppelt -- die Orchestrierung beider Ports macht der
# Use-Case ``ManageSchedules`` (M.6 Schritt 2), nicht das Repository.


class ScheduleRepository(Protocol):
    """REINE Persistenz der ``scan_schedules``-Tabelle (keine Job-Engine).

    Gibt rohe ``dict``-Zeilen heraus (alle neun Spalten), KEIN Domaenen-Modell:
    die CRUD-Response ist ein 1:1-Tabellen-Dump fuer ``/api/schedules`` ohne
    Domaenen-Sicht/Auswahl -- ein ``dataclass`` waere hier verhaltensloser
    Persistenz-Ballast (anders als ``ScanSummary``, das eine bewusste Teil-Sicht
    strukturiert). Die einzige Schedule-Logik (``parse_schedule``) sitzt in
    ``domain.monitoring``, nicht in einem Zeilen-Modell.
    """

    def list(self) -> list[dict[str, Any]]:
        """Alle Schedules als rohe Zeilen-dicts, nach ``id`` sortiert.

        Leere Tabelle -> ``[]``, niemals ``None``. Form wie Altcode
        ``get_schedules()`` (neun Spalten: id/name/cidr/profile_id/schedule/
        enabled/last_run/next_run/created_at).
        """
        ...

    def add(self, name: str, cidr: str, profile_id: str, schedule: str) -> int:
        """Legt eine Schedule-Zeile an (``enabled=1``) und gibt die neue ``id`` zurueck.

        REIN Persistenz: registriert KEINEN Job (die Altcode-Kopplung an
        ``_register_job`` macht in v2 der Use-Case). Der ``schedule``-String wird
        hier NICHT geparst -- ungeparst gespeichert, das Parsen passiert beim
        Job-Registrieren (so landet auch ein -- noch -- unparsbarer String in der
        Liste; siehe ``ManageSchedules``-best-effort, M.6 Schritt 2).
        """
        ...

    def update(self, schedule_id: int, enabled: bool | None, name: str | None) -> None:
        """Aktualisiert ``enabled`` und/oder ``name`` (``None`` = unveraendert lassen).

        REIN Persistenz. BEFUND (charakterisierungstreu bewahrt, NICHT in M.6
        gefixt): Der Altcode entfernt bei ``enabled=False`` NICHT den laufenden Job
        -- ein deaktiviertes Schedule laeuft weiter. Das ist ein latenter Bug; der
        Fix (``enabled=False`` -> ``unregister``) gaebe ``UpdateSchedule`` spaeter
        den Job-Port dazu, ist aber ein bewusster eigener Schritt, kein M.6-Auftrag.
        """
        ...

    def delete(self, schedule_id: int) -> None:
        """Loescht die Schedule-Zeile. Idempotent (kein Fehler bei fehlender id).

        REIN Persistenz: entfernt KEINEN Job (der Use-Case ruft zusaetzlich
        ``ScanJobScheduler.unregister``).
        """
        ...


class ScanJobScheduler(Protocol):
    """Die APScheduler-Job-Engine -- Lifecycle + Job-Registrierung (kein DB-Zugriff).

    Kapselt ``AsyncIOScheduler`` hinter dem Port. Kennt scanning NICHT: ``register``
    nimmt einen generischen ``ScanTriggerCallback``, den die Engine bei Faelligkeit
    ruft -- die Verdrahtung an den scanning-Use-Case macht der Composition Root
    (``app.py``, M.9). Das Parsen des Schedule-Strings nutzt die reine
    ``domain.parse_schedule``; ein ``ScheduleParseError`` propagiert an den Aufrufer
    (``ManageSchedules`` faengt ihn best-effort).
    """

    def start(self, callback: ScanTriggerCallback) -> None:
        """Startet die Engine und registriert die bereits gespeicherten, aktiven Schedules.

        Der ``callback`` wird fuer jede Job-Ausloesung verwendet. Idempotenz/
        Doppelstart-Schutz ist Adapter-Sache.
        """
        ...

    def stop(self) -> None:
        """Faehrt die Engine herunter (laufende Jobs werden nicht abgewartet)."""
        ...

    def register(self, schedule: dict[str, Any], callback: ScanTriggerCallback) -> None:
        """Registriert (oder ersetzt) den Job fuer eine Schedule-Zeile.

        ``schedule`` ist eine Repo-Zeile (id/cidr/profile_id/schedule ...). Der
        Adapter parst ``schedule["schedule"]`` via ``domain.parse_schedule`` und
        baut den APScheduler-Trigger -- ein ``ScheduleParseError`` propagiert
        (kein stiller 24h-Fallback). ``replace_existing`` (Altcode-treu).
        """
        ...

    def unregister(self, schedule_id: int) -> None:
        """Entfernt den Job einer Schedule-id. Idempotent -- ein nie registrierter
        (oder schon entfernter) Job ist KEIN Fehler (best-effort + Log im Adapter).
        """
        ...


# ── SLA (M.7) ───────────────────────────────────────────────────────────────
# NUR die LESE-Seite. Der Schreibpfad (``record``) ist BEWUSST ausgelassen: im
# Altcode wird ``sla_samples`` NIE geschrieben (``modules/sla.record_sample`` wird
# importiert, aber nirgends gerufen) -- der Loop schreibt rtt_history + monitor_events,
# nicht sla_samples. ``/api/sla`` liefert darum dauerhaft ``[]``.
#
# Diesen toten Strang zu BELEBEN (record(sample) in den Port + der M.5-RunMonitor
# ruft ihn pro tick) ist ein bewusster eigener Use-Case-Schritt (M.7b), NICHT Teil
# von M.7. Begruendung der Schnittlinie (Asymmetrie zur rtt_history.alive-Wurzel
# aus M.4): Der alive-Fix war ADDITIV am bestehenden rtt_repo.save -- der Loop
# schrieb ohnehin RTT, die Spalte kam an Ort dazu, kein Eingriff in den Use-Case.
# Ein sla-Schreibpfad dagegen RIESSE den abgeschlossenen, getesteten M.5-Use-Case
# wieder auf (neuer Port im Konstruktor + neue tick-Zeile + Test-Update) -- fuer
# einen Effekt, der vor M.9 unsichtbar bleibt (die /api/sla-Endpunkte sind bis dahin
# Altcode). Latente Befunde nicht mitten in der Migrations-Phase fixen, sondern als
# eigenen sichtbaren Schritt -- wie der enabled=False->unregister-Fix in M.6.


class SlaSampleRepository(Protocol):
    """REINE Lese-Persistenz der ``sla_samples``-Tabelle (Altcode ``modules/sla.py``).

    Speist die reinen Domaenen-Funktionen ``compute_sla_stats`` / ``build_hourly_chart``
    (M.2): die Methoden geben die geladenen Sample-Zeilen als ``SlaSample`` heraus
    (``(alive, rtt_ms, ts)`` -- exakt die Spaltenreihenfolge der Altcode-Query und das
    Eingabeformat der Domaenen-Funktionen). KEIN ``record`` -- s. Modul-Kommentar (M.7b).
    """

    def samples_for(self, target_id: str, since: float) -> list[SlaSample]:
        """Sample-Zeilen eines Targets ab ``since`` (absoluter Timestamp), chronologisch.

        Reproduziert die Altcode-Query ``SELECT alive, rtt_ms, ts FROM sla_samples
        WHERE target_id=? AND ts>? ORDER BY ts``. ``since`` ist ein ABSOLUTER ts-Wert
        -- die ``now - days*86400``-Rechnung macht der Use-Case, das Repo bleibt
        zeitlogik-frei (Muster ``RttHistoryRepository.recent(limit)``). Reihenfolge
        AUFSTEIGEND (``ORDER BY ts``), wie der Altcode, damit die Hourly-Buckets der
        Domaene stimmen. Keine Daten / unbekanntes Target -> ``[]``, niemals ``None``.
        """
        ...

    def target_ids(self) -> list[str]:
        """Alle target_ids mit mindestens einem Sample (Altcode ``SELECT DISTINCT``).

        Speist ``GetAllSlaStats`` (M.7): je id eine Gesamtstatistik. Leere Tabelle ->
        ``[]``, niemals ``None``. Da ``sla_samples`` im Altcode nie geschrieben wird,
        ist die Liste real dauerhaft leer (-> ``/api/sla == []``); s. Modul-Kommentar.
        """
        ...


# ── Langzeit-Logging (B-I) ──────────────────────────────────────────────────
# Die Persistenz-Vertraege des opt-in Logging-Kerns (Domaene
# ``domain.monitoring.logging_task``). GETRENNT vom fluechtigen Live-Monitor: das
# sind EIGENE Tabellen (``monitoring_log_*``), NICHT ``rtt_history``/``monitor_events``
# -- der Live-Loop bleibt unberuehrt. Drei Belange, drei Vertraege:
#
# * ``LoggingTaskRepository`` -- die Task-DEFINITIONEN (Lebenszyklus, upsert, da der
#   ``state`` ueber die Lebenszeit wandert; kein reines Append wie die Messdaten).
# * ``LoggingRttRepository`` -- die dichten RTT-Messpunkte je Task (Retention 1 Monat).
# * ``LoggingEventRepository`` -- die Ereignis-/Anomalie-Flanken je Task (Retention
#   1 Jahr).
#
# Beide Mess-Repos sind reine Append-Stores mit zeit-basierter Retention
# (``delete_older_than``) -- die Zeitlogik (``now - 30d`` / ``now - 365d``) liegt beim
# Aufrufer (Schritt 3 / B-II), die Repos nehmen einen ABSOLUTEN ``cutoff_ts`` (Muster
# ``SlaSampleRepository.samples_for(since)``: das Repo bleibt uhrfrei). Sync wie alle
# Persistenz-Ports der Domaene (sqlite ist schnell genug, kein executor).


class LoggingTaskRepository(Protocol):
    """Persistenz der Logging-Aufgaben-DEFINITIONEN (Tabelle ``monitoring_log_tasks``).

    Haelt die ``LoggingTask``-Lebenszyklus-Objekte -- KEIN reines Append: der
    ``state`` einer Aufgabe wandert ueber ihre Lebenszeit (``CREATED`` -> ``ACTIVE``
    <-> ``PAUSED`` -> ``FINISHED``), darum ist ``save`` ein UPSERT anhand ``task.id``
    (Insert ODER Update). Speist die spaetere Konfliktpruefung (``conflicts_with``
    braucht alle Aufgaben am Ziel) und die Uebersicht -- darum ``list_all``. Die
    Mess-DATEN (RTT, Events) liegen in eigenen Repos; ``delete`` loescht NUR die
    Definition.
    """

    def save(self, task: LoggingTask) -> None:
        """Legt ``task`` ab oder aktualisiert die bestehende Definition (Upsert ueber ``id``).

        Insert beim ersten Mal, Update bei jedem weiteren ``save`` derselben ``id``
        (z. B. nach einem Zustandsuebergang ``start``/``pause``/``stop``, der einen
        NEUEN ``LoggingTask`` mit gewechseltem ``state`` liefert). Die Enums
        (``capture_mode``/``operation_mode``/``state``) werden als ihr ``str``-Wert
        abgelegt; ``save`` schreibt KEINE Uhr (``created_at`` kommt aus dem ``task``).
        """
        ...

    def get(self, task_id: str) -> LoggingTask | None:
        """Laedt EINE Aufgaben-Definition anhand ihrer ``id`` (Enum-Round-trip).

        Unbekannte ``id`` -> ``None`` (kein Fehler) -- der EINZIGE ``None``-Rueckgabe-
        Punkt dieser Ports (eine fehlende Einzel-Definition ist ein legitimer Zustand,
        anders als die Listen-Methoden, die ``[]`` liefern). Die gespeicherten
        Enum-Strings werden via ``CaptureMode``/``OperationMode``/``TaskState``
        zurueck in die Domaenen-Enums gehoben.
        """
        ...

    def list_all(self) -> list[LoggingTask]:
        """Alle Aufgaben-Definitionen (fuer Uebersicht + Konfliktpruefung).

        Speist die Domaenen-``conflicts_with`` (sie braucht alle Aufgaben am selben
        Ziel) und die UI-Uebersicht. Leere Tabelle -> ``[]``, niemals ``None``.
        """
        ...

    def delete(self, task_id: str) -> None:
        """Loescht NUR die Aufgaben-Definition (die Messdaten liegen separat).

        Idempotent: eine unbekannte ``id`` ist kein Fehler (Muster
        ``ScheduleRepository.delete``). Die zugehoerigen RTT-/Event-Messpunkte werden
        hier NICHT mitgeloescht -- das ist ein eigener Belang (eigene Repos +
        Retention), den dieser Vertrag bewusst nicht vermischt.
        """
        ...


class LoggingRttRepository(Protocol):
    """Persistenz der dichten RTT-Messpunkte je Logging-Aufgabe (Retention 1 Monat).

    Reiner Append-Store (Tabelle ``monitoring_log_rtt``): EIN Messpunkt pro ``save``,
    nie ein Update. Anders als ``RttHistoryRepository`` (Live-Monitor) gibt es hier
    KEINEN Zeilen-Cap pro Ziel -- die Mengenbegrenzung laeuft ueber die zeit-basierte
    Retention (``delete_older_than``), nicht ueber ein Trim. ``range`` gibt benannte
    Domaenen-``LoggingRttSample`` heraus (s. Domaenen-Docstring: vier Felder ->
    benannt statt Tuple).
    """

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        """Legt einen RTT-Messpunkt fuer ``task_id`` ab (Append, nie Update).

        ``ts`` ist Unix-ts; der RTT-Sentinel ``-1.0`` (nicht erreichbar) wird
        unveraendert gespeichert (Muster ``RttHistoryRepository``). KEIN Trim -- die
        Mengenbegrenzung uebernimmt ``delete_older_than`` (Retention).
        """
        ...

    def range(self, task_id: str, since: float, until: float) -> list[LoggingRttSample]:
        """Messpunkte eines Tasks im Zeitfenster ``[since, until)``, chronologisch aufsteigend.

        ``since`` INKLUSIV, ``until`` EXKLUSIV (Halb-offen ``ts >= since AND ts <
        until``) -- konsistent mit dem Zeitfenster-Praedikat der Domaene
        (``is_window_active``: Start inklusiv, Ende exklusiv), damit kein Messpunkt
        an einer Fenstergrenze doppelt in zwei aneinandergrenzende Bereiche faellt.
        Beide Grenzen sind ABSOLUTE ts-Werte (das Repo bleibt uhrfrei, Muster
        ``SlaSampleRepository.samples_for``). Reihenfolge AUFSTEIGEND (``ORDER BY
        ts``). Keine Daten / unbekannter Task -> ``[]``, niemals ``None``.
        """
        ...

    def all_for(self, task_id: str) -> list[LoggingRttSample]:
        """ALLE Messpunkte eines Tasks, chronologisch aufsteigend (``ORDER BY ts``).

        Speist den Logging-SLA-Use-Case (C-3): die SLA-Kennzahlen rechnen ueber den
        GESAMTEN vorhandenen Task-Zeitraum, nicht ueber ein ``days``-Fenster. Anders
        als ``range`` (halb-offenes Zeitfenster) gibt es hier BEWUSST keine ts-Grenzen
        -- kein ``since``/``until``-Hack mit Magic-Grenzwerten: ein Logging-Task hat ein
        klar begrenztes eigenes Fenster, und die zeit-basierte Retention
        (``delete_older_than``, 1 Monat) begrenzt "alle" ohnehin nach oben. Reihenfolge
        AUFSTEIGEND, damit die Hourly-Buckets der Domaene stimmen (Muster ``range``).
        Keine Daten / unbekannter Task -> ``[]``, niemals ``None``.
        """
        ...

    def delete_older_than(self, cutoff_ts: float) -> int:
        """Loescht alle Messpunkte ALTER als ``cutoff_ts`` und gibt die Zeilenzahl zurueck.

        Retention-Mechanik: ``ts < cutoff_ts`` (strikt aelter; ein Punkt GENAU auf
        dem Cutoff bleibt, symmetrisch zur ``since``-Inklusivitaet von ``range``).
        ``cutoff_ts`` ist absolut -- die ``now - 30d``-Rechnung macht der Aufrufer
        (Schritt 3 / B-II), nicht das Repo. Rueckgabe = Zahl geloeschter Zeilen
        (fuer Log/Mengen-Check). Nichts zu loeschen -> ``0``.
        """
        ...

    def count(self) -> int:
        """Gesamtzahl gespeicherter RTT-Messpunkte (ueber alle Tasks).

        Fuer den spaeteren Mengen-Check (Schritt 3 / B-II: Retention/Storage-
        Beobachtung). Leere Tabelle -> ``0``.
        """
        ...


class LoggingEventRepository(Protocol):
    """Persistenz der Ereignis-/Anomalie-Flanken je Logging-Aufgabe (Retention 1 Jahr).

    Reiner Append-Store (Tabelle ``monitoring_log_events``), Muster wie
    ``MonitorEventRepository``. Der ``event_type`` ist bewusst ein ROHER ``str`` am
    Port-Rand (NICHT der Live-Monitor-``MonitorEventType``): der Logging-Kern ist vom
    fluechtigen Live-Monitor GETRENNT (Domaenen-Docstring) -- ihn an dessen
    up/down-Vokabular zu koppeln, wuerde diese Trennung an der Persistenz-Naht wieder
    aufweichen und das Logging-Event-Vokabular fuer immer an die Live-Monitor-Enum
    binden. Der rohe ``str`` haelt die Naht offen (das fachliche Logging-Event-
    Vokabular wird von B-II definiert, nicht hier vorweggenommen) -- Muster
    ``monitor_events.event TEXT``, das den Wert ebenfalls als String am Rand fuehrt.
    """

    def save(self, task_id: str, event_type: str, rtt_ms: float, ts: float) -> None:
        """Legt eine Ereignis-Flanke fuer ``task_id`` ab (Append, nie Update).

        ``event_type`` als roher ``str`` (s. Klassen-Docstring), ``ts`` Unix-ts,
        ``rtt_ms`` der Messwert an der Flanke (Sentinel ``-1.0`` erlaubt). KEIN Trim
        -- die Mengenbegrenzung uebernimmt ``delete_older_than``.
        """
        ...

    def range(self, task_id: str, since: float, until: float) -> list[LoggingEventRow]:
        """Ereignisse eines Tasks im Zeitfenster ``[since, until)``, chronologisch aufsteigend.

        Halb-offenes Fenster (``since`` inklusiv, ``until`` exklusiv) + absolute
        ts-Grenzen + aufsteigende Reihenfolge -- EXAKT wie ``LoggingRttRepository.range``
        (gemeinsame Fenster-Semantik des Logging-Kerns). Keine Daten / unbekannter
        Task -> ``[]``, niemals ``None``.
        """
        ...

    def delete_older_than(self, cutoff_ts: float) -> int:
        """Loescht Ereignisse ALTER als ``cutoff_ts`` und gibt die Zeilenzahl zurueck.

        Retention-Mechanik wie ``LoggingRttRepository.delete_older_than`` (``ts <
        cutoff_ts``, absoluter Cutoff vom Aufrufer, Rueckgabe = geloeschte Zeilen) --
        nur die Retention-SPANNE unterscheidet sich (1 Jahr statt 1 Monat), und die
        liegt beim Aufrufer, nicht im Repo. Nichts zu loeschen -> ``0``.
        """
        ...
