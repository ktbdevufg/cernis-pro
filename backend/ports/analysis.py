"""Ports der analysis-Domaene: Regelquelle + Aufloesung der Hilfe-URL.

Zwei Vertraege, getrennt nach Belang:

* ``RuleProvider`` -- die QUELLE der Regeln. Bewusst ein eigener Port, damit die Regeln
  spaeter aus Datei/DB kommen koennen, OHNE die Domaene anzufassen (ein zweiter Adapter
  hinter demselben Port -- dasselbe Muster wie der spaetere eBPF-Adapter hinter den
  traffic-Ports). Der erste Adapter liefert schlicht die eingebauten
  ``domain.analysis.DEFAULT_RULES``. Synchron: ein reiner In-Memory-Lookup ohne I/O
  (Muster ``ports.scanning.VendorLookupPort.lookup`` -- ebenfalls synchron, weil kein
  Netz-/Loop-I/O). Eine leere Regelliste ist ein gueltiger Zustand (``()``), kein Fehler.

* ``HelpLinkResolver`` -- loest einen ``HelpKind`` in eine konkrete Hilfe-URL auf. Vision
  6.4: die URL ist INFRASTRUKTUR (eine pflegbare Lookup-Tabelle hinter einem Port), nicht
  Domaene -- so laesst sie sich aendern, ohne den Domaenen-Ring anzufassen. Synchron und
  bewusst rein lokal: der Resolver ruft NICHTS ab, er liefert nur die hinterlegte URL --
  das bewusste-Klick-/Privacy-Prinzip (Vision 4.4) bleibt gewahrt, weil hier kein
  Netzverkehr entsteht. Ein unbekannter ``help_kind`` liefert ``""`` (legitimer
  Leer-Zustand "keine Hilfe-URL hinterlegt", KEIN Fehler -- Muster
  ``ports.scanning.HostnameResolverPort.resolve`` gibt ``""`` statt zu werfen).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie process/traffic/scanning).
Die Vertragspruefung traegt mypy statisch und die Verdrahtung im Composition Root
(``app.py``), nicht ``isinstance`` zur Laufzeit.

``ports/`` kennt NUR ``domain/analysis``-Typen + stdlib/typing. KEIN ``infrastructure/``-
und kein ``api/``-Import -- import-linter-Contract "ports kennen hoechstens domain".
"""

from typing import Protocol

from domain.analysis import HelpKind, Rule


class RuleProvider(Protocol):
    """Quelle der analysis-Regeln (eigener Port, damit Datei/DB-Adapter spaeter passt)."""

    def get_rules(self) -> tuple[Rule, ...]:
        """Liefert die aktuell gueltigen Regeln als Tuple.

        Synchron: ein reiner In-Memory-Lookup ohne I/O -- der erste Adapter gibt die
        eingebauten ``domain.analysis.DEFAULT_RULES`` zurueck. Eine leere Regelliste
        (``()``) ist ein gueltiger Zustand (keine Regeln -> keine Beobachtungen), KEIN
        Fehler.
        """
        ...


class HelpLinkResolver(Protocol):
    """Loest einen ``HelpKind`` in eine konkrete Hilfe-URL auf (Vision 6.4: URL = Infra)."""

    def resolve(self, help_kind: HelpKind) -> str:
        """Gibt die hinterlegte Hilfe-URL zum ``help_kind`` zurueck -- rein lokal.

        Synchron und ohne jedes Netz-I/O: der Resolver ruft NICHTS ab, er schlaegt die
        URL nur in einer lokalen Tabelle nach (Vision 4.4: kein Verkehr ohne bewussten
        Klick). Ein unbekannter ``help_kind`` -> ``""`` (legitimer Leer-Zustand "keine
        URL hinterlegt", KEIN Fehler).
        """
        ...
