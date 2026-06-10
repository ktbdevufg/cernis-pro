"""Adapter der analysis-Domaene (AN.3) -- die zwei Ports hinter zustandslosen Implementierungen.

Aeusserer Ring: ``infrastructure/`` darf ``domain/`` importieren, NIEMALS ``application/``
oder ``api/`` (import-linter-Contract "infrastructure kennt nicht application/api"). Beide
Adapter hier sind ZUSTANDSLOS -- reine In-Memory-Lookups ohne I/O (analysis ist eine reine
Lese-/Rechen-Domaene wie process: kein Poller, kein State).

* ``BuiltinRuleProvider`` -- erster Adapter hinter ``ports.analysis.RuleProvider``. Liefert
  schlicht die eingebauten ``domain.analysis.DEFAULT_RULES``. Ein spaeterer Datei-/DB-Adapter
  ersetzt ihn hinter DEMSELBEN Port, OHNE die Domaene anzufassen (dasselbe Muster wie ein
  spaeterer eBPF-Adapter hinter den traffic-Ports).

* ``StaticHelpLinkResolver`` -- erster Adapter hinter ``ports.analysis.HelpLinkResolver``.
  Loest einen ``HelpKind`` ueber eine lokale Lookup-Tabelle in eine konkrete Hilfe-URL auf.
  Vision 6.4: die URL ist INFRASTRUKTUR (eine pflegbare Tabelle hinter einem Port), nicht
  Domaene -- so laesst sie sich aendern, ohne den Domaenen-Ring anzufassen. Bewusst rein
  lokal: der Resolver ruft NICHTS ab, er liefert nur die hinterlegte URL (Vision 4.4: kein
  Verkehr ohne bewussten Klick -- die URL wird geliefert, nicht abgerufen). Die hinterlegten
  Ziele sind langlebige, allgemein anerkannte Ressourcen (Wikipedia), KEINE projekteigene
  Domain. Ein unbekannter ``help_kind`` -> ``""`` (legitimer Leer-Zustand, KEIN Fehler).
"""

from typing import ClassVar

from domain.analysis import DEFAULT_RULES, HelpKind, Rule


class BuiltinRuleProvider:
    """Liefert die eingebauten ``DEFAULT_RULES`` -- erster Adapter hinter ``RuleProvider``.

    Zustandslos, synchron: ein reiner In-Memory-Lookup ohne I/O. Ein spaeterer
    Datei-/DB-Adapter tritt hinter denselben Port, ohne die Domaene zu beruehren.
    """

    def get_rules(self) -> tuple[Rule, ...]:
        return DEFAULT_RULES


class StaticHelpLinkResolver:
    """Loest einen ``HelpKind`` ueber eine lokale Tabelle in eine Hilfe-URL auf.

    Vision 6.4: die URL ist Infrastruktur, pflegbar ohne Domaenen-Eingriff. Rein lokaler
    Lookup (kein Netz-I/O); ein unbekannter ``help_kind`` -> ``""`` (Leer-Zustand, kein
    Fehler).
    """

    # Lokale Lookup-Tabelle HelpKind -> URL. Langlebige, allgemein anerkannte Ressourcen
    # (Wikipedia), bewusst KEINE projekteigene Domain -- so bleibt die URL pflegbar, ohne
    # einen Domaenen-Eingriff. Ein neuer HelpKind bringt hier genau einen neuen Eintrag mit.
    _HELP_URLS: ClassVar[dict[HelpKind, str]] = {
        "process_suspicious_path": "https://de.wikipedia.org/wiki/Ausf%C3%BChrbare_Datei",
        "process_masquerade": "https://de.wikipedia.org/wiki/Rootkit",
        "remote_access_port": "https://de.wikipedia.org/wiki/Liste_der_standardisierten_Ports",
        "high_connection_count": "https://de.wikipedia.org/wiki/Netzwerk-Socket",
        "new_host": "https://de.wikipedia.org/wiki/Address_Resolution_Protocol",
    }

    def resolve(self, help_kind: HelpKind) -> str:
        # ``dict.get`` mit Leer-Default: ein nicht hinterlegter Kind ist ein gueltiger
        # Leer-Zustand ("keine Hilfe-URL"), KEIN Fehler (Vertrag des Ports).
        return self._HELP_URLS.get(help_kind, "")
