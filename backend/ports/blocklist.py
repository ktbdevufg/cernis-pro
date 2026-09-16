"""Ports der blocklist-Domaene: Persistenz-Vertraege fuer Quellen und Eintraege.

Zwei Repository-Vertraege, getrennt nach Persistenz-Belang -- Muster wie
``ports/outbound_log.py``:

* ``BlocklistSourceRepository`` -- die Quellen-DEFINITIONEN (Tabelle
  ``blocklist_sources``; Upsert, da ``status``/``enabled``/``entry_count`` ueber die
  Lebenszeit wandern -- kein reines Append).
* ``BlocklistEntryRepository`` -- die geparsten EINTRAEGE, indiziert (Tabelle
  ``blocklist_entries``), getrennt nach Domain- vs IP-Eintraegen ueber ein ``kind``-Feld.

``ports/`` kennt NUR ``domain.blocklist``-Typen + stdlib. KEIN ``modules``- und kein
``infrastructure``-Import (import-linter-Contract "ports kennen hoechstens domain").
Der Import von ``domain.blocklist`` ist erlaubt -- so duerfen Adapter, die diesen
Vertrag erfuellen, die reine Domaenenfunktion ``ip_in_cidr`` fuer den CIDR-Lookup nutzen.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie outbound_log/monitoring/
devices). Die Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung im
Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

Alle Methoden sind ``sync`` (Muster der Persistenz-Repos der Nachbar-Domaenen: sqlite
ist schnell genug, kein executor).
"""

from typing import Protocol

from domain.blocklist import BlocklistSource

__all__ = ["BlocklistEntryRepository", "BlocklistSourceRepository"]


# ── Quellen-Definitionen ──────────────────────────────────────────────────────


class BlocklistSourceRepository(Protocol):
    """Persistenz der Quellen-DEFINITIONEN (Tabelle ``blocklist_sources``).

    Haelt die ``BlocklistSource``-Objekte. KEIN reines Append: ``status``, ``enabled``,
    ``last_fetched_ts`` und ``entry_count`` einer Quelle wandern ueber ihre Lebenszeit,
    darum ist ``upsert`` ein Insert ODER Update anhand ``source.id``. Die Mess-DATEN
    (geparste Eintraege) liegen im getrennten ``BlocklistEntryRepository``.
    """

    def upsert(self, source: BlocklistSource) -> None:
        """Legt ``source`` ab oder aktualisiert die bestehende Definition (Upsert ueber ``id``).

        Insert beim ersten Mal, Update bei jedem weiteren ``upsert`` derselben ``id``
        (z. B. nach einem Lade-Lauf, der ``status``/``last_fetched_ts``/``entry_count``
        fortschreibt). Die Enums (``group``/``fmt``/``origin``/``status``) werden als ihr
        ``str``-Wert abgelegt; ``bool`` als 0/1.
        """
        ...

    def get(self, source_id: str) -> BlocklistSource | None:
        """Laedt EINE Quellen-Definition anhand ihrer ``id`` (Enum-Round-trip).

        Unbekannte ``id`` -> ``None`` (kein Fehler). Die gespeicherten Enum-Strings
        werden via ``BlocklistGroup``/``BlocklistFormat``/``SourceOrigin``/
        ``BlocklistStatus`` zurueck in die Domaenen-Enums gehoben.
        """
        ...

    def list_all(self) -> list[BlocklistSource]:
        """Alle Quellen-Definitionen, sortiert nach ``group``, dann ``name`` (aufsteigend).

        Speist die UI-Uebersicht. Leere Tabelle -> ``[]``, niemals ``None``.
        """
        ...

    def delete(self, source_id: str) -> None:
        """Loescht NUR die Quellen-Definition (die geparsten Eintraege liegen separat).

        Idempotent: eine unbekannte ``id`` ist kein Fehler. Die zugehoerigen Eintraege
        (``blocklist_entries``) werden hier NICHT mitgeloescht -- das ist ein eigener
        Belang (``BlocklistEntryRepository.delete_for``), den dieser Vertrag nicht
        vermischt.
        """
        ...

    def clear_all(self) -> None:
        """Leert alle Quellen-Definitionen (nur die eigene Tabelle ``blocklist_sources``)."""
        ...


# ── Geparste Eintraege ────────────────────────────────────────────────────────


class BlocklistEntryRepository(Protocol):
    """Persistenz der geparsten EINTRAEGE einer Quelle (Tabelle ``blocklist_entries``).

    Getrennt nach Domain- vs IP-Eintraegen ueber ein ``kind``-Feld (``"domain"`` |
    ``"ip_cidr"``). Das Repo liefert ALLE Treffer; das Filtern nach ``enabled`` und
    Anzeige-Strenge ist Application-Belang (das Repo weiss NICHT, welche Quellen aktiv
    sind). Der Lookup laeuft ueber indizierte Spalten (Set-Lookup bzw. CIDR-Iteration).
    """

    def replace_entries(self, source_id: str, domains: list[str], ip_cidrs: list[str]) -> None:
        """Ersetzt ALLE Eintraege einer ``source_id`` durch die neuen (eine Transaktion).

        Loescht zuerst saemtliche bisherigen Eintraege dieser ``source_id`` und schreibt
        dann die neuen ``domains`` (``kind='domain'``) und ``ip_cidrs``
        (``kind='ip_cidr'``) -- alles in EINER Transaktion (atomarer Austausch, kein
        Zwischenzustand mit halber Liste). Die ``domains`` kommen bereits lowercased/
        normalisiert herein (der Parser hat sie ueber ``normalize_domain`` gefuehrt).
        """
        ...

    def delete_for(self, source_id: str) -> None:
        """Loescht alle Eintraege einer ``source_id`` (idempotent, unbekannt -> 0 Zeilen)."""
        ...

    def count_for(self, source_id: str) -> int:
        """Zahl der gespeicherten Eintraege einer ``source_id`` (Domain + IP). Leer -> ``0``."""
        ...

    def lookup_domains(self, candidates: list[str]) -> list[tuple[str, str]]:
        """Treffer je uebergebenem Suffix-Kandidaten -> ``(source_id, matched_domain)``.

        Set-Lookup ueber die indizierte Spalte (``kind='domain' AND value IN (...)``).
        Der Aufrufer reicht die ``domain_suffix_candidates`` herein; das Repo liefert je
        Treffer ein Paar ``(source_id, getroffene_Domain)`` -- ueber ALLE Quellen (das
        Filtern nach ``enabled``/Strenge macht die Application). Keine Treffer / leere
        Kandidatenliste -> ``[]``.
        """
        ...

    def lookup_ips(self, ip: str) -> list[tuple[str, str]]:
        """Treffer fuer ``ip`` -> ``(source_id, matched_cidr)`` je Treffer.

        Exakte ``/32``-/``/128``-Treffer laufen ueber den indizierten Gleichheits-Lookup
        (``value = ip`` oder ``value = ip || '/32'`` bzw. ``'/128'``). Echte Netze
        (Praefix kleiner als ``/32`` bzw. ``/128``) werden geladen und per
        ``domain.blocklist.ip_in_cidr`` geprueft -- der Import von ``domain`` ist im
        ports-Ring erlaubt, der praktische Aufruf liegt im Adapter. Einfach und korrekt:
        bei wenigen tausend CIDR-Eintraegen (FireHOL L1) ist lineare Pruefung akzeptabel.
        Keine Treffer -> ``[]``.
        """
        ...

    def clear_all(self) -> None:
        """Leert alle Eintraege (nur die eigene Tabelle ``blocklist_entries``)."""
        ...
