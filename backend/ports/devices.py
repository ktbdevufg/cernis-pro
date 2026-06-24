"""Ports der devices-Domaene: Vertraege fuer Persistenz und Zeit.

Zwei getrennte Vertraege:

* ``DeviceRepository`` -- REINE Persistenz (Variante A): CRUD, IP-History und
  Zaehler. Das Repository kennt KEINE Merge-Logik. Die Upsert-Regel
  (``merge_scan``) und die History-Regel (``should_append_ip``) leben in
  ``domain/devices``; die Orchestrierung "lesen -> mergen -> schreiben"
  uebernimmt der Use-Case (D.5).
* ``Clock`` -- die EINE Zeitquelle. Loest die UTC/lokal-Inkonsistenz des
  Altcodes strukturell: niemand in Domaene/Use-Case ruft ``datetime.now()``,
  die Zeit kommt ueber diesen Port (Adapter in D.4, Verdrahtung in app.py/D.6).

Bewusste Entscheidung: KEIN ``@runtime_checkable``. Die Vertragspruefung laeuft
statisch ueber mypy und ueber die Verdrahtung im Composition Root (``app.py``),
nicht zur Laufzeit per ``isinstance``.

Import von ``domain`` ist erlaubt -- der import-linter-Contract verbietet nur die
Gegenrichtung (domain -> ports) sowie Importe aus ``infrastructure``/``api``.
"""

from datetime import datetime
from typing import Protocol

from domain.devices import Device, DeviceStats, IpHistoryEntry


class DeviceRepository(Protocol):
    """Reine Persistenz fuer Geraete + IP-History + Zaehler (keine Merge-Logik)."""

    def get(self, mac: str) -> Device | None:
        """Ein Geraet anhand der MAC, oder ``None`` wenn nicht vorhanden.

        ``None`` ist ein legitimer Zustand ("nicht bekannt"), kein Fehler.
        """
        ...

    def get_all(self, known_only: bool) -> list[Device]:
        """Alle Geraete, ``last_seen`` absteigend (neueste zuerst).

        ``known_only=True`` filtert auf ``is_known``. Leerer Bestand -> ``[]``,
        niemals ``None``. Die Sortierung ist Sache des Adapters.
        """
        ...

    def get_unclassified(self) -> list[Device]:
        """Die Wache-Liste: Geraete mit ``is_known=0 AND watch_dismissed=0``.

        Noch nie eingeordnete (``is_known`` False) und nicht weggelegte
        (``watch_dismissed`` False) Geraete, ``last_seen`` absteigend (neueste
        zuerst). Leerer Bestand -> ``[]``, niemals ``None``. Die Sortierung ist
        Sache des Adapters.
        """
        ...

    def get_archived(self) -> list[Device]:
        """Alle archivierten Geraete (``archived=1``), ``last_seen`` absteigend.

        Das Archiv-Gegenstueck zu ``get_all`` (das archivierte Geraete
        ausblendet): hier kommen genau die heraus, die aus den Wertungen und
        Listen weggeraeumt, aber nicht geloescht wurden. Leerer Bestand -> ``[]``,
        niemals ``None``. Die Sortierung ist Sache des Adapters.
        """
        ...

    def get_archive_candidates(self, not_seen_since: datetime) -> list[Device]:
        """Geraete, die fuer die Archiv-Nachfrage in Frage kommen.

        Liefert die Geraete, die ``archived=0`` UND ``archive_prompt_dismissed=0``
        sind UND deren ``last_seen <= not_seen_since`` liegt (seit der Schwelle
        nicht mehr gesehen), ``last_seen`` aufsteigend (am laengsten verschollene
        zuerst). Die Zeitgrenze ``not_seen_since`` kommt VOM Use-Case
        (``now - threshold``), nicht aus dem Repo -- so gibt es keine versteckte
        Uhr in der Persistenz (Muster ``stats``). Leerer Bestand -> ``[]``,
        niemals ``None``. Die Sortierung ist Sache des Adapters.
        """
        ...

    def save(self, device: Device) -> None:
        """Upsert auf ``device.mac`` -- legt an oder aktualisiert.

        Nimmt bewusst das fertig gemergte Domaenen-Objekt; das Mergen ist VORHER
        im Use-Case (mit ``domain.merge_scan``) passiert, nicht hier.
        """
        ...

    def delete(self, mac: str) -> None:
        """Loescht das Geraet UND seine zugehoerige IP-History.

        BUG-1-FIX: keine Halbloeschung wie im Altcode (der nur ``known_devices``
        traf und ``devices``/``device_ip_history`` verwaist liess). Idempotent --
        kein Fehler bei fehlender MAC.
        """
        ...

    def append_ip_history(self, entry: IpHistoryEntry) -> None:
        """Haengt einen IP-History-Eintrag an.

        OB angehaengt wird, entscheidet der Use-Case via
        ``domain.should_append_ip`` -- das Repository fuehrt nur aus.
        """
        ...

    def get_ip_history(self, mac: str, limit: int = 20) -> list[IpHistoryEntry]:
        """IP-History eines Geraets, neueste zuerst, auf ``limit`` begrenzt.

        Unbekannte MAC -> ``[]``.
        """
        ...

    def stats(self, active_since: datetime) -> DeviceStats:
        """Aggregierte Zaehler. ``active`` = Geraete mit ``last_seen >= active_since``.

        Die Zeitgrenze kommt VOM Use-Case (z. B. ``now - 24h``), nicht aus dem
        Repo -- so gibt es keine versteckte Uhr in der Persistenz.
        """
        ...

    def clear_all(self) -> None:
        """Leert Geraete UND ihre IP-History (nur die eigenen Tabellen)."""
        ...


class Clock(Protocol):
    """Die EINE Zeitquelle der Anwendung."""

    def now(self) -> datetime:
        """Aktueller Zeitpunkt als timezone-aware UTC-``datetime``.

        Einzige Zeitquelle fuer Domaene und Use-Cases; loest die UTC/lokal-
        Vermischung des Altcodes (Schema-Default UTC vs. ``datetime.now()`` lokal)
        strukturell auf.
        """
        ...
