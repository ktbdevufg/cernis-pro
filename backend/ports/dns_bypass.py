"""Ports des DNS-Umgehungs-Waechters: Query-Quelle + Persistenz-Vertraege (ADR 0042).

Neben dem schlanken Query-Quellen-Vertrag drei Repository-Vertraege, getrennt nach
Persistenz-Belang -- Muster wie die drei outbound_log-Repos
(``OutboundRecordingRepository`` / ``OutboundDetailRepository`` /
``OutboundAggregateRepository``):

* ``DnsBypassRecordingRepository`` -- die Aufzeichnungs-DEFINITIONEN (Lebenszyklus,
  Upsert, da der ``state`` ueber die Lebenszeit wandert; kein reines Append).
* ``DnsBypassDetailRepository`` -- der rohe DETAIL-Zeitverlauf je Aufzeichnung (reiner
  Append-Store mit zeit-basierter Retention).
* ``DnsBypassAggregateRepository`` -- die verdichteten Datensaetze je (Aufzeichnung,
  Quell-Geraet, Ziel-Resolver) (Upsert ueber den zusammengesetzten Schluessel).

``ports/`` kennt NUR ``domain.dns_bypass``-Typen + stdlib. KEIN ``modules``- und kein
``infrastructure``-Import (import-linter-Contract "ports kennen hoechstens domain"). Die
Lese-Record-Typen (``DnsBypassDetailRow``, ``AggregatedBypass``) kommen aus
``domain.dns_bypass`` -- der Ring definiert KEINE eigenen Datentraeger.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie blocklist/outbound_log/
monitoring). Die Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung im
Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

Alle Repo-Methoden sind ``sync`` (Muster der Persistenz-Repos der Nachbar-Domaenen:
sqlite ist schnell genug, kein executor).
"""

from collections.abc import Sequence
from typing import Protocol

from domain.dns_bypass import (
    AggregatedBypass,
    DnsBypassDetailRow,
    DnsBypassRecording,
    RawDnsQuery,
)

__all__ = [
    "DnsBypassAggregateRepository",
    "DnsBypassDetailRepository",
    "DnsBypassRecordingRepository",
    "DnsQueryProvider",
]


class DnsQueryProvider(Protocol):
    """Liefert die aktuell vom Sniffer erkannten DNS-Anfragen (Snapshot).

    Quellen-AGNOSTISCH: gibt ``RawDnsQuery``-Records zurueck (KEIN Fremd-Domaenentyp). Die
    echte Quelle -- der ``DnsHelperClient``-poll (Etappe 1) -- faellt erst im Composition
    Root. Synchron, weil die echte Quelle ein lokaler Snapshot des zuletzt gepollten
    Standes ist.
    """

    def __call__(self) -> Sequence[RawDnsQuery]:
        """Aktuell vom Sniffer erkannte DNS-Anfragen (Snapshot)."""
        ...


# ── Aufzeichnungs-Definitionen ──────────────────────────────────────────────


class DnsBypassRecordingRepository(Protocol):
    """Persistenz der Aufzeichnungs-DEFINITIONEN (Tabelle ``dns_bypass_recordings``).

    Haelt die ``DnsBypassRecording``-Lebenszyklus-Objekte -- KEIN reines Append: der
    ``state`` einer Aufzeichnung wandert ueber ihre Lebenszeit (``CREATED`` -> ``ACTIVE``
    -> ``FINISHED``), darum ist ``save`` ein UPSERT anhand ``recording.id`` (Insert ODER
    Update). Die Mess-DATEN (Detail/Aggregat) liegen in eigenen Repos; ``delete`` loescht
    NUR die Definition (Muster ``OutboundRecordingRepository``).
    """

    def save(self, recording: DnsBypassRecording) -> None:
        """Legt ``recording`` ab oder aktualisiert die bestehende Definition (Upsert ueber ``id``).

        Insert beim ersten Mal, Update bei jedem weiteren ``save`` derselben ``id`` (z. B.
        nach einem Zustandsuebergang ``start``/``stop``, der einen NEUEN
        ``DnsBypassRecording`` mit gewechseltem ``state`` liefert). Der ``state`` wird als
        sein ``str``-Wert abgelegt; ``save`` schreibt KEINE Uhr (``created_at`` kommt aus
        dem ``recording``).
        """
        ...

    def get(self, recording_id: str) -> DnsBypassRecording | None:
        """Laedt EINE Aufzeichnungs-Definition anhand ihrer ``id`` (Enum-Round-trip).

        Unbekannte ``id`` -> ``None`` (kein Fehler) -- der einzige ``None``-Rueckgabe-Punkt
        dieser Ports (eine fehlende Einzel-Definition ist ein legitimer Zustand, anders als
        die Listen-Methoden, die ``[]`` liefern). Der gespeicherte Enum-String wird via
        ``DnsBypassRecordingState`` zurueck in das Domaenen-Enum gehoben.
        """
        ...

    def list_all(self) -> list[DnsBypassRecording]:
        """Alle Aufzeichnungs-Definitionen, nach ``created_at`` sortiert (aufsteigend).

        Speist die UI-Uebersicht. Leere Tabelle -> ``[]``, niemals ``None``.
        """
        ...

    def delete(self, recording_id: str) -> None:
        """Loescht NUR die Aufzeichnungs-Definition (die Messdaten liegen separat).

        Idempotent: eine unbekannte ``id`` ist kein Fehler (Muster
        ``OutboundRecordingRepository.delete``). Die zugehoerigen Detail-/Aggregat-
        Messpunkte werden hier NICHT mitgeloescht -- das ist ein eigener Belang (eigene
        Repos), den dieser Vertrag bewusst nicht vermischt.
        """
        ...

    def clear_all(self) -> None:
        """Leert alle Aufzeichnungs-Definitionen (nur die eigene Tabelle).

        Wie ``delete`` betrifft das NUR die Definitionen -- die Messdaten (Detail/Aggregat)
        liegen in eigenen Repos und werden hier nicht mitgeleert.
        """
        ...


# ── Detail-Zeitverlauf ──────────────────────────────────────────────────────


class DnsBypassDetailRepository(Protocol):
    """Persistenz des rohen DETAIL-Zeitverlaufs je Aufzeichnung (Append, Retention).

    Reiner Append-Store (Tabelle ``dns_bypass_detail``): EINE Umgehungs-Anfrage pro
    ``save``, nie ein Update. Es gibt KEINEN Zeilen-Cap je Aufzeichnung -- die
    Mengenbegrenzung laeuft ueber die zeit-basierte Retention (``delete_older_than``),
    nicht ueber ein Trim (Muster ``OutboundDetailRepository``). ``range`` gibt den
    benannten Domaenen-Record ``DnsBypassDetailRow`` heraus.
    """

    def save(
        self,
        recording_id: str,
        ts: float,
        src_ip: str,
        dst_ip: str,
        l4: str,
        qname: str,
    ) -> None:
        """Legt einen DETAIL-Messpunkt fuer ``recording_id`` ab (Append, nie Update).

        ``ts`` ist Unix-ts. ``qname`` darf ``""`` sein (Sniffer liefert ihn best-effort).
        KEIN Trim -- die Mengenbegrenzung uebernimmt ``delete_older_than`` (Retention).
        """
        ...

    def range(self, recording_id: str, since: float, until: float) -> list[DnsBypassDetailRow]:
        """Messpunkte einer Aufzeichnung im Zeitfenster ``[since, until)``, chronologisch.

        ``since`` INKLUSIV, ``until`` EXKLUSIV (Halb-offen ``ts >= since AND ts < until``)
        -- damit kein Messpunkt an einer Fenstergrenze doppelt in zwei aneinandergrenzende
        Bereiche faellt (Muster ``OutboundDetailRepository.range``). Beide Grenzen sind
        ABSOLUTE ts-Werte (das Repo bleibt uhrfrei). Reihenfolge AUFSTEIGEND
        (``ORDER BY ts``). Keine Daten / unbekannte Aufzeichnung -> ``[]``, niemals
        ``None``.
        """
        ...

    def delete_older_than(self, cutoff_ts: float) -> int:
        """Loescht alle Messpunkte ALTER als ``cutoff_ts`` und gibt die Zeilenzahl zurueck.

        Retention-Mechanik: ``ts < cutoff_ts`` (strikt aelter; ein Punkt GENAU auf dem
        Cutoff bleibt, symmetrisch zur ``since``-Inklusivitaet von ``range``).
        ``cutoff_ts`` ist absolut -- die ``now - ...``-Rechnung macht der Aufrufer, nicht
        das Repo. Rueckgabe = Zahl geloeschter Zeilen. Nichts zu loeschen -> ``0``.
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


class DnsBypassAggregateRepository(Protocol):
    """Persistenz der verdichteten Datensaetze je (Aufzeichnung, Quell-IP, Ziel-IP).

    Haelt je ``(recording_id, src_ip, dst_ip)`` GENAU einen ``AggregatedBypass`` (Tabelle
    ``dns_bypass_aggregate``, zusammengesetzter PRIMARY KEY). ``upsert`` ueberschreibt den
    bestehenden Datensatz (INSERT OR REPLACE) -- der Merge-Lesepfad des spaeteren Sinks
    liest ueber ``get`` den Vorzustand und schreibt den verdichteten Stand zurueck (Muster
    ``OutboundAggregateRepository``).
    """

    def upsert(self, recording_id: str, aggregate: AggregatedBypass) -> None:
        """Legt den verdichteten Datensatz ab oder ueberschreibt ihn (INSERT OR REPLACE).

        Schluessel ist ``(recording_id, aggregate.src_ip, aggregate.dst_ip)``: ein zweiter
        ``upsert`` derselben Kombination ERSETZT die bestehende Zeile (keine zweite Zeile).
        Der Merge selbst (``domain.merge_bypass``) passiert beim Aufrufer -- das Repo legt
        nur den fertigen ``AggregatedBypass`` ab.
        """
        ...

    def get(self, recording_id: str, src_ip: str, dst_ip: str) -> AggregatedBypass | None:
        """Laedt den verdichteten Datensatz einer ``(recording_id, src_ip, dst_ip)``-Kombination.

        Fuer den Merge-Lesepfad des spaeteren Sinks (Vorzustand vor ``merge_bypass``).
        Unbekannte Kombination -> ``None`` (kein Fehler).
        """
        ...

    def list_for(self, recording_id: str) -> list[AggregatedBypass]:
        """Alle verdichteten Datensaetze einer Aufzeichnung, lauteste zuerst (stabil).

        Reihenfolge ``ORDER BY query_count DESC, src_ip ASC, dst_ip ASC`` -- die
        anfragestaerkste (Geraet, Resolver)-Gruppe zuerst, bei Gleichstand stabil nach
        ``src_ip`` dann ``dst_ip`` aufsteigend. Keine Daten / unbekannte Aufzeichnung ->
        ``[]``, niemals ``None``.
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
