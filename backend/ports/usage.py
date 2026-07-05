"""Port (Vertrag) der usage-Zaehlung -- Persistenz der Funktions-Aufrufzaehler.

EIN Persistenz-Vertrag (``sync`` -- lokaler SQLite-Zugriff, Muster der uebrigen Repos):

* ``UsageStatsRepository`` -- zaehlt Funktions-Oeffnungen je stabilem ``feature_id`` und
  liefert die Rangliste (``top``) sowie den Gesamtstand (``get_all``).

``UsageRecord`` ist ein reiner, framework-freier Read-View am Port-Rand (frozen dataclass,
Muster ``ports.cve.InventoryHost``): ``feature_id`` + ``count`` + ``last_used``. KEINE
Geschaeftslogik -- nur die Form, in der Adapter und Use-Cases die Zaehlstaende austauschen.

BEWUSST KEIN eigenes ``domain``-Subpaket: die usage-Zaehlung traegt keine Domaenenlogik
(kein Regelwerk, keine Invariante ausser "count >= 0"), nur einen Zaehler pro Schluessel.
Der Read-View gehoert darum an den Port-Rand, nicht in einen neuen Domaenen-Ring.

``feature_id`` ist ein STABILER String-Schluessel vom Frontend (z. B. ``"observe:scan"``,
``"investigate:cve"``, ``"reporting"``). Der Port validiert ihn NICHT gegen eine feste
Liste -- das Backend zaehlt nur, offen fuer neue Funktionen ohne Backend-Aenderung.

``ports/`` kennt nur stdlib (import-linter "ports kennen hoechstens domain"). KEIN
``@runtime_checkable`` (Muster der uebrigen Domaenen -- statische Pruefung ueber mypy +
Verdrahtung im Composition Root).
"""

from dataclasses import dataclass
from typing import Protocol

__all__ = ["UsageRecord", "UsageStatsRepository"]


@dataclass(frozen=True)
class UsageRecord:
    """Ein Zaehlstand je Funktion -- der Read-View der usage-Zaehlung.

    ``feature_id`` ist der stabile Frontend-Schluessel, ``count`` die Zahl der bisherigen
    Oeffnungen (>= 0), ``last_used`` der ISO-8601-UTC-Zeitstempel der letzten Oeffnung
    (``None``, solange die Funktion noch nie geoeffnet wurde -- fuer einen frisch per DEFAULT
    angelegten Eintrag gaebe es keinen; in der Praxis traegt jeder gezaehlte Record ihn).
    """

    feature_id: str
    count: int
    last_used: str | None


class UsageStatsRepository(Protocol):
    """Persistenz-Vertrag der Funktions-Aufrufzaehler (Upsert + Rangliste + Gesamtstand)."""

    def increment(self, feature_id: str) -> None:
        """Erhoeht den Zaehler fuer ``feature_id`` um 1 und setzt ``last_used`` = jetzt.

        Upsert: existiert der Schluessel noch nicht, wird er mit ``count = 1`` angelegt;
        sonst wird der bestehende Zaehler erhoeht. Synchron (lokaler SQLite-Zugriff).
        """
        ...

    def top(self, limit: int = 5) -> list["UsageRecord"]:
        """Liefert die ``limit`` meistgeoeffneten Funktionen, absteigend nach ``count``.

        Tiebreaker bei Gleichstand: ``last_used`` absteigend (die juengst genutzte zuerst).
        Weniger als ``limit`` vorhandene Eintraege -> entsprechend kuerzere Liste; keine
        Eintraege -> ``[]`` (gueltiger Leer-Zustand, kein Fehler).
        """
        ...

    def get_all(self) -> list["UsageRecord"]:
        """Liefert ALLE gespeicherten Zaehlstaende (ungefiltert). Leer -> ``[]``."""
        ...
