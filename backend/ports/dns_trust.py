"""Port des DNS-Server-Vertrauensmodells: Persistenz-Vertrag (ADR 0043, Etappe 1).

EIN Repository-Vertrag ``DnsTrustRepository`` fuer die kuratierten DNS-Server. Der
Record-Typ ``TrustedDnsServer`` kommt aus ``domain.dns_trust`` -- der ports-Ring
definiert KEINEN eigenen Datentraeger (Muster der Nachbar-Ports: der Ring kennt
hoechstens ``domain``-Typen + stdlib, KEIN ``modules``- und kein
``infrastructure``-Import).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie blocklist/
outbound_log/dns_bypass). Die Vertragspruefung laeuft statisch ueber mypy und
ueber die Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per
``isinstance``.

Alle Methoden sind ``sync`` (Muster der Persistenz-Repos der Nachbar-Domaenen:
sqlite ist schnell genug, kein executor).
"""

from typing import Protocol

from domain.dns_trust import DnsTrustState, TrustedDnsServer

__all__ = ["DnsTrustRepository"]


class DnsTrustRepository(Protocol):
    """Persistenz der kuratierten DNS-Server (Schluessel: ``ip``, kanonisch).

    Haelt je ``ip`` GENAU einen ``TrustedDnsServer``. ``upsert`` legt an ODER
    ueberschreibt; ``set_trust`` aendert NUR den Vertrauens-Zustand (+ ``last_seen``)
    und laesst Kategorie/``first_seen`` unberuehrt. Die Ableitung von Kategorie und
    Vor-Vertrauen ist reine Domaenen-Logik beim Aufrufer -- das Repo legt nur den
    fertigen Record ab.
    """

    def upsert(self, server: TrustedDnsServer) -> None:
        """Legt ``server`` ab oder ueberschreibt den bestehenden (Upsert ueber ``ip``).

        ``ip`` ist der Primaerschluessel: ein zweiter ``upsert`` derselben ``ip``
        ERSETZT die bestehende Zeile (keine zweite Zeile). Der ``trust_state`` und
        die ``category`` werden als ihr ``str``-Wert abgelegt; ``upsert`` schreibt
        KEINE Uhr (``first_seen``/``last_seen`` kommen aus dem ``server``).
        """
        ...

    def get(self, ip: str) -> TrustedDnsServer | None:
        """Laedt EINEN Server anhand seiner ``ip`` (Enum-Round-trip).

        Unbekannte ``ip`` -> ``None`` (kein Fehler) -- eine fehlende Einzel-Zeile
        ist ein legitimer Zustand, anders als ``list_all`` (das ``[]`` liefert).
        Die gespeicherten Enum-Strings werden zurueck in die Domaenen-Enums gehoben.
        """
        ...

    def list_all(self) -> list[TrustedDnsServer]:
        """Alle kuratierten Server, nach ``first_seen`` sortiert (aufsteigend).

        Speist die UI-Uebersicht. Leere Tabelle -> ``[]``, niemals ``None``.
        """
        ...

    def set_trust(self, ip: str, state: DnsTrustState, now: float) -> None:
        """Aendert NUR den Vertrauens-Zustand (+ ``last_seen``) eines Servers.

        ``category`` und ``first_seen`` bleiben unberuehrt -- dies ist der schmale
        Schreibpfad der reinen Uebergaenge (``trust``/``reject``/``reset``), nicht
        ein voller ``upsert``. Der neue ``state`` wird als sein ``str``-Wert abgelegt,
        ``last_seen`` auf ``now`` gesetzt. ``now`` ist absolut (Unix-ts) -- das Repo
        bleibt uhrfrei. Unbekannte ``ip`` schreibt nichts (0 Zeilen betroffen).
        """
        ...

    def delete(self, ip: str) -> None:
        """Loescht den Server mit ``ip``.

        Idempotent: eine unbekannte ``ip`` ist kein Fehler (DELETE betrifft 0 Zeilen).
        """
        ...

    def clear_all(self) -> None:
        """Leert alle kuratierten Server (nur die eigene Tabelle)."""
        ...
