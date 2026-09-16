"""Port des metrics-Querschnitts: der EINE Lesevertrag fuer den Export (M.8).

EIN Querschnitts-Lesevertrag statt Wiederverwendung der vier Quell-Repos
(DeviceRepository / RttHistoryRepository / SlaSampleRepository /
ScanHistoryRepository). Begruendung der Schnittlinie: die metrics-Aggregate sind
ANDERE Queries, als die Quell-Repos anbieten --

* devices: ZWEI Aktiv-Fenster (1h UND 24h) in einem Snapshot; ``DeviceRepository.
  stats`` liefert nur EIN Fenster pro Aufruf.
* rtt_history: LATEST-pro-Target ueber ALLE Targets in einem Zeitfenster;
  ``RttHistoryRepository.recent`` liefert die Historie EINES Targets.
* sla_samples: 24h-``GROUP BY target_id``-Aggregat (uptime%/avg_rtt); die M.7-Lese-
  seite liefert rohe Samples fuer ``compute_sla_stats`` (days/chart -- anderer Belang).
* scan_history: ``COUNT(7d)`` + ``MAX(host_count)``-Aggregat; ``ScanHistoryRepository.
  list`` liefert eine Summary-Liste.

Die vier Quell-Repos wiederzuverwenden hiesse: vier Fremd-Ports im Use-Case UND die
Aggregation trotzdem neu rechnen (recent->latest-Reduktion, stats 2x, list->max/count,
sla-24h-GROUP-BY) -- mehr Kopplung ohne echte DRY-Ersparnis. Ein eigener
``MetricsReader`` ist das ``SlaSampleRepository``-Muster: ein schlanker,
zweckgebundener Lesevertrag, dessen Adapter die SQL-Aggregate kapselt.

FUENFTE Quelle ``alert_history`` (A.7b): in M.8 bewusst ausgelassen (alerting war nicht
migriert -> ein direkter Lese-Block waere Vorwaerts-Kopplung an eine nicht-existente
v2-Domaene gewesen). Ab A.7a beschreibt der monitor-Trigger ``alert_history`` real, darum
freigeschaltet: der Adapter zaehlt die 24h-Zeilen DIREKT per SQL (M.8-Trennung -- metrics
kennt die TABELLE, nicht den alerting-Port). Charakterisierungstreu rendert nur
``to_prometheus`` das Feld (Altcode: ``cernis_alerts_24h`` nur dort; influx/HA nie). Die
Port-Signatur aendert sich NICHT -- ``snapshot()`` gibt weiter ``MetricsSnapshot``, nur um
das ``alerts_24h``-Feld erweitert.

leere-DB-Robustheit (M.8, bewusste v2-Verbesserung): ``snapshot`` wirft NICHT bei
leerer/fehlender Tabelle -- jede Quelle liefert dann ``0``/``[]`` (der Null-Snapshot
ist valide). Das heilt den Altcode-Bug (Device-Block ohne inneres try -> ganze
ERROR-Zeile bei leerer DB).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster settings/devices/scanning/
monitoring). Vertragspruefung statisch ueber mypy + Verdrahtung im Composition Root.
``snapshot`` ist ``sync`` (Muster der anderen Lese-Repos: sqlite ist schnell genug,
kein executor).

``ports/`` kennt NUR ``domain``-Typen + stdlib. Import von ``domain.metrics`` ist
erlaubt (nur die Gegenrichtung domain->ports ist verboten).
"""

from typing import Protocol

from domain.metrics import MetricsSnapshot


class MetricsReader(Protocol):
    """Liest den vollstaendigen metrics-Lese-Querschnitt als ``MetricsSnapshot``."""

    def snapshot(self) -> MetricsSnapshot:
        """Aktueller metrics-Querschnitt ueber die fuenf Quellen.

        Aggregiert frisch aus devices / rtt_history / sla_samples / scan_history /
        alert_history: Device-Zaehler inkl. beider Aktiv-Fenster (1h/24h), latest-RTT
        pro Target, 24h-SLA-Aggregat pro Target, 7d-Scan-Aggregat, 24h-Alert-COUNT
        (A.7b). Die zwei Zeitkonventionen der
        Quellen (epoch-float ``ts`` fuer rtt/sla, ISO-Text ``last_seen``/
        ``scanned_at`` fuer devices/scan) bedient der Adapter -- BEWUSST nicht
        vereinheitlicht (Altcode-IST).

        Leere/fehlende Quell-Tabelle -> die jeweiligen Felder ``0`` bzw. die Listen
        ``[]`` (kein Throw, keine ERROR-Zeile). Der Null-Snapshot ist ein valider
        Zustand -> valide leere/0-Export-Ausgabe.
        """
        ...
