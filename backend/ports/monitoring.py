"""Ports der monitoring-Domaene: Vertraege fuer den Live-Connectivity-Loop (M.5).

Sechs Vertraege, gruppiert nach Loop-Belang:

* **Messung** -- ``MonitorPingerPort`` (pingt ein Target -> PingSample).
* **Konsequenzen** -- ``MonitorNotifierPort`` (Notification), ``MonitorBroadcasterPort``
  (Live-Update an die Subscriber).
* **Persistenz** -- ``RttHistoryRepository`` (rtt_history), ``MonitorEventRepository``
  (monitor_events).
* **Konfiguration** -- ``MonitorTargetSource`` (welche Targets ueberwachen?).

SCOPE (M.3): NUR die Loop-Ports. Die scheduler-/sla-/metrics-Vertraege kommen mit
ihrer Phase (M.6/M.7/M.8) -- ein Port ohne seinen Adapter+Use-Case waere ein toter
Vertrag mit Signatur, die sich erst beim Adapter-Bau zeigt. Jeder GEZOGENE Port ist
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

from typing import Protocol

from domain.monitoring import (
    MonitorEvent,
    MonitorEventType,
    MonitorTarget,
    PingSample,
)

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
