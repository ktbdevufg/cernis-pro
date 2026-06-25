"""Ports der outbound_log-Domaene: Persistenz-Vertraege der Aussenkontakte-Aufzeichnung.

Drei Repository-Vertraege, getrennt nach Persistenz-Belang -- Muster wie die drei
Logging-Repos in ``ports/monitoring`` (``LoggingTaskRepository`` /
``LoggingRttRepository`` / ``LoggingEventRepository``):

* ``OutboundRecordingRepository`` -- die Aufzeichnungs-DEFINITIONEN (Lebenszyklus,
  Upsert, da der ``state`` ueber die Lebenszeit wandert; kein reines Append).
* ``OutboundDetailRepository`` -- der rohe DETAIL-Zeitverlauf je Aufzeichnung (reiner
  Append-Store mit zeit-basierter Retention).
* ``OutboundAggregateRepository`` -- die verdichteten Datensaetze je (Aufzeichnung, IP)
  (Upsert ueber den zusammengesetzten Schluessel, Merge-Lesepfad des spaeteren Sinks).

``ports/`` kennt NUR ``domain.outbound_log``-Typen + stdlib. KEIN ``modules``- und
kein ``infrastructure``-Import -- import-linter-Contract "ports kennen hoechstens
domain". Der Ring definiert KEINE eigenen Datentraeger: der Lese-Record
``OutboundDetailRow`` lebt in ``domain.outbound_log`` (Muster ``LoggingRttSample``
aus ``domain.monitoring``), nicht hier.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie monitoring/devices/
scanning). Die Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung
im Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

Alle Methoden sind ``sync`` (Muster der Persistenz-Repos der Nachbar-Domaenen: sqlite
ist schnell genug, kein executor).
"""

from typing import Protocol

from domain.outbound_log import (
    AggregatedContact,
    OutboundDetailRow,
    OutboundRecording,
)

# ── Definitionen ──────────────────────────────────────────────────────────


class OutboundRecordingRepository(Protocol):
    """Persistenz der Aufzeichnungs-DEFINITIONEN (Tabelle ``outbound_log_recordings``).

    Haelt die ``OutboundRecording``-Lebenszyklus-Objekte -- KEIN reines Append: der
    ``state`` einer Aufzeichnung wandert ueber ihre Lebenszeit (``CREATED`` ->
    ``ACTIVE`` <-> ``PAUSED`` -> ``FINISHED``), darum ist ``save`` ein UPSERT anhand
    ``recording.id`` (Insert ODER Update). Die Mess-DATEN (Detail/Aggregat) liegen in
    eigenen Repos; ``delete`` loescht NUR die Definition (Muster
    ``LoggingTaskRepository``).
    """

    def save(self, recording: OutboundRecording) -> None:
        """Legt ``recording`` ab oder aktualisiert die bestehende Definition (Upsert ueber ``id``).

        Insert beim ersten Mal, Update bei jedem weiteren ``save`` derselben ``id``
        (z. B. nach einem Zustandsuebergang ``start``/``pause``/``resume``/``stop``, der
        einen NEUEN ``OutboundRecording`` mit gewechseltem ``state`` liefert). Die Enums
        (``mode``/``depth``/``state``) werden als ihr ``str``-Wert abgelegt; ``save``
        schreibt KEINE Uhr (``created_at`` kommt aus dem ``recording``).
        """
        ...

    def get(self, recording_id: str) -> OutboundRecording | None:
        """Laedt EINE Aufzeichnungs-Definition anhand ihrer ``id`` (Enum-Round-trip).

        Unbekannte ``id`` -> ``None`` (kein Fehler) -- der einzige ``None``-Rueckgabe-
        Punkt dieser Ports (eine fehlende Einzel-Definition ist ein legitimer Zustand,
        anders als die Listen-Methoden, die ``[]`` liefern). Die gespeicherten
        Enum-Strings werden via ``RecordingMode``/``DetailDepth``/``RecordingState``
        zurueck in die Domaenen-Enums gehoben.
        """
        ...

    def list_all(self) -> list[OutboundRecording]:
        """Alle Aufzeichnungs-Definitionen, nach ``created_at`` sortiert (aufsteigend).

        Speist die UI-Uebersicht. Leere Tabelle -> ``[]``, niemals ``None``.
        """
        ...

    def delete(self, recording_id: str) -> None:
        """Loescht NUR die Aufzeichnungs-Definition (die Messdaten liegen separat).

        Idempotent: eine unbekannte ``id`` ist kein Fehler (Muster
        ``LoggingTaskRepository.delete``). Die zugehoerigen Detail-/Aggregat-Messpunkte
        werden hier NICHT mitgeloescht -- das ist ein eigener Belang (eigene Repos), den
        dieser Vertrag bewusst nicht vermischt.
        """
        ...

    def clear_all(self) -> None:
        """Leert alle Aufzeichnungs-Definitionen (nur die eigene Tabelle).

        Wie ``delete`` betrifft das NUR die Definitionen -- die Messdaten (Detail/
        Aggregat) liegen in eigenen Repos und werden hier nicht mitgeleert.
        """
        ...


# ── Detail-Zeitverlauf ──────────────────────────────────────────────────────


class OutboundDetailRepository(Protocol):
    """Persistenz des rohen DETAIL-Zeitverlaufs je Aufzeichnung (Append, Retention).

    Reiner Append-Store (Tabelle ``outbound_log_detail``): EIN Messpunkt pro ``save``,
    nie ein Update. Es gibt KEINEN Zeilen-Cap je Aufzeichnung -- die Mengenbegrenzung
    laeuft ueber die zeit-basierte Retention (``delete_older_than``), nicht ueber ein
    Trim (Muster ``LoggingRttRepository``). ``range`` gibt den benannten Domaenen-
    Record ``OutboundDetailRow`` heraus.
    """

    def save(
        self,
        recording_id: str,
        ts: float,
        remote_ip: str,
        remote_port: int | None,
        hostname: str | None,
        country: str | None,
        operator: str | None,
        asn: str | None,
        app_name: str | None,
        pid: int | None,
        connection_count: int,
    ) -> None:
        """Legt einen DETAIL-Messpunkt fuer ``recording_id`` ab (Append, nie Update).

        ``ts`` ist Unix-ts. Die Anreicherungsfelder duerfen ``None`` sein (nicht
        ermittelbar) und werden als NULL abgelegt. KEIN Trim -- die Mengenbegrenzung
        uebernimmt ``delete_older_than`` (Retention).
        """
        ...

    def range(self, recording_id: str, since: float, until: float) -> list[OutboundDetailRow]:
        """Messpunkte einer Aufzeichnung im Zeitfenster ``[since, until)``, chronologisch.

        ``since`` INKLUSIV, ``until`` EXKLUSIV (Halb-offen ``ts >= since AND ts <
        until``) -- damit kein Messpunkt an einer Fenstergrenze doppelt in zwei
        aneinandergrenzende Bereiche faellt (Muster ``LoggingRttRepository.range``).
        Beide Grenzen sind ABSOLUTE ts-Werte (das Repo bleibt uhrfrei). Reihenfolge
        AUFSTEIGEND (``ORDER BY ts``). Keine Daten / unbekannte Aufzeichnung -> ``[]``,
        niemals ``None``.
        """
        ...

    def delete_older_than(self, cutoff_ts: float) -> int:
        """Loescht alle Messpunkte ALTER als ``cutoff_ts`` und gibt die Zeilenzahl zurueck.

        Retention-Mechanik: ``ts < cutoff_ts`` (strikt aelter; ein Punkt GENAU auf dem
        Cutoff bleibt, symmetrisch zur ``since``-Inklusivitaet von ``range``).
        ``cutoff_ts`` ist absolut -- die ``now - ...``-Rechnung macht der Aufrufer,
        nicht das Repo. Rueckgabe = Zahl geloeschter Zeilen. Nichts zu loeschen -> ``0``.
        """
        ...

    def count(self) -> int:
        """Gesamtzahl gespeicherter DETAIL-Messpunkte (ueber alle Aufzeichnungen).

        Fuer den spaeteren Mengen-Check (Retention/Storage-Beobachtung). Leere Tabelle
        -> ``0``.
        """
        ...

    def clear_all(self) -> None:
        """Leert alle DETAIL-Messpunkte (nur die eigene Tabelle)."""
        ...


# ── Aggregate ───────────────────────────────────────────────────────────────


class OutboundAggregateRepository(Protocol):
    """Persistenz der verdichteten Datensaetze je (Aufzeichnung, Remote-IP).

    Haelt je ``(recording_id, remote_ip)`` GENAU einen ``AggregatedContact`` (Tabelle
    ``outbound_log_aggregate``, zusammengesetzter PRIMARY KEY). ``upsert`` ueberschreibt
    den bestehenden Datensatz (INSERT OR REPLACE) -- der Merge-Lesepfad des spaeteren
    Sinks liest ueber ``get`` den Vorzustand und schreibt den verdichteten Stand zurueck.
    """

    def upsert(self, recording_id: str, contact: AggregatedContact) -> None:
        """Legt den verdichteten Datensatz ab oder ueberschreibt ihn (INSERT OR REPLACE).

        Schluessel ist ``(recording_id, contact.remote_ip)``: ein zweiter ``upsert``
        derselben Kombination ERSETZT die bestehende Zeile (keine zweite Zeile). Der
        Merge selbst (``domain.merge_contact``) passiert beim Aufrufer -- das Repo legt
        nur den fertigen ``AggregatedContact`` ab.
        """
        ...

    def get(self, recording_id: str, remote_ip: str) -> AggregatedContact | None:
        """Laedt den verdichteten Datensatz einer ``(recording_id, remote_ip)``-Kombination.

        Fuer den Merge-Lesepfad des spaeteren Sinks (Vorzustand vor ``merge_contact``).
        Unbekannte Kombination -> ``None`` (kein Fehler).
        """
        ...

    def list_for(self, recording_id: str) -> list[AggregatedContact]:
        """Alle verdichteten Datensaetze einer Aufzeichnung, lauteste zuerst (stabil).

        Reihenfolge ``ORDER BY total_count DESC, remote_ip ASC`` -- die kontaktstaerkste
        Gegenstelle zuerst, bei Gleichstand stabil nach ``remote_ip`` aufsteigend. Keine
        Daten / unbekannte Aufzeichnung -> ``[]``, niemals ``None``.
        """
        ...

    def delete_for(self, recording_id: str) -> None:
        """Loescht ALLE Aggregate einer Aufzeichnung (alle Zeilen der ``recording_id``).

        Idempotent: eine unbekannte ``recording_id`` ist kein Fehler (DELETE betrifft
        0 Zeilen). Trifft NUR die genannte Aufzeichnung -- die Aggregate anderer
        Aufzeichnungen bleiben unberuehrt.
        """
        ...

    def count(self) -> int:
        """Gesamtzahl gespeicherter Aggregate (ueber alle Aufzeichnungen). Leer -> ``0``."""
        ...

    def clear_all(self) -> None:
        """Leert alle Aggregate (nur die eigene Tabelle)."""
        ...
