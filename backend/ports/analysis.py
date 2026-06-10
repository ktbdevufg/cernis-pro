"""Ports der analysis-Domaene: Regelquelle + Aufloesung der Hilfe-URL.

Drei Vertraege, getrennt nach Belang:

* ``RuleProvider`` -- die QUELLE der Regeln (LESE-Port der Engine). Bewusst ein eigener
  Port, damit die Regeln spaeter aus Datei/DB kommen koennen, OHNE die Domaene anzufassen
  (ein zweiter Adapter hinter demselben Port -- dasselbe Muster wie der spaetere eBPF-
  Adapter hinter den traffic-Ports). Der erste Adapter liefert schlicht die eingebauten
  ``domain.analysis.DEFAULT_RULES``. Synchron: ein reiner In-Memory-Lookup ohne I/O
  (Muster ``ports.scanning.VendorLookupPort.lookup`` -- ebenfalls synchron, weil kein
  Netz-/Loop-I/O). Eine leere Regelliste ist ein gueltiger Zustand (``()``), kein Fehler.

* ``UserRuleStore`` -- der VERWALTUNGS-Port fuer benutzer-eigene Regeln (A.2). BEWUSST
  getrennt vom ``RuleProvider``: jener ist NUR die Lese-Quelle der Engine, dieser ist der
  validierende Schreib-/Verwaltungs-Vertrag, den die Verwaltungs-Use-Cases (``AddUserRules``
  /``ListUserRules``) nutzen. Der SQLite-Adapter erfuellt BEIDE Ports (``get_rules`` deckt
  beide ab; ``add_rules``/``delete_rule`` gehoeren nur hierher). ``add_rules`` validiert
  gestuft (error -> nichts gespeichert, Issues zurueck; nur warning -> gespeichert + warnings
  gemeldet) und gibt die Befunde als ``list[RuleIssue]`` zurueck -- KEINE Exception fuer den
  fachlichen Ablehnungsfall.

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

from collections.abc import Sequence
from typing import Protocol

from domain.analysis import HelpKind, Rule, RuleIssue


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


class UserRuleStore(Protocol):
    """Verwaltungs-Vertrag fuer benutzer-eigene Regeln (A.2) -- getrennt vom RuleProvider.

    Der ``RuleProvider`` bleibt der reine Lese-Port der Engine; ``UserRuleStore`` ist der
    Schreib-/Verwaltungs-Port, den ``AddUserRules``/``ListUserRules`` nutzen. Der SQLite-
    Adapter erfuellt beide. ``get_rules`` ist deckungsgleich mit ``RuleProvider.get_rules``
    (ein Store IST eine Regelquelle). Synchron -- der Adapter ist ein lokaler SQLite-Zugriff
    ohne Loop-/Netz-I/O.
    """

    def get_rules(self) -> tuple[Rule, ...]:
        """Liefert die GESPEICHERTEN eigenen Regeln (ohne die eingebauten Defaults)."""
        ...

    def add_rules(self, new_rules: Sequence[Rule]) -> list[RuleIssue]:
        """Validiert und speichert neue Regeln gestuft; gibt die Befunde zurueck.

        Enthaelt das Ergebnis einen ``error``-``RuleIssue`` (kaputt oder ``duplicate_id``),
        wird NICHTS gespeichert (keine Teil-Speicherung). Nur ``warning`` (oder leer) ->
        gespeichert und die warnings gemeldet. KEINE Exception fuer die fachliche Ablehnung
        -- die Befunde sind der Rueckgabewert (der api-Rand macht aus ``error`` ein 422).
        """
        ...

    def delete_rule(self, rule_id: str) -> None:
        """Loescht eine gespeicherte eigene Regel."""
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
