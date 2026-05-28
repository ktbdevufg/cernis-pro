"""Adapter fuer ``VendorLookupPort`` -- duenner Wrapper um ``modules.vendor``.

Der Hersteller-Lookup ist ein reiner In-Memory-OUI-Lookup (kein I/O): Die
OUI-Datenbank wird einmalig aus ``oui.json`` geladen und ``modules.lookup_vendor``
cached das Ergebnis (``lru_cache``). Darum bleibt ``lookup`` SYNCHRON -- genau wie
der Port es vorgibt (ADR-konform, kein ``run_in_executor``).

Altmuster-Befund (NICHT hier reproduziert): ``modules.vendor._load_db`` faellt
STILL auf eine leere DB (``{}``) zurueck, wenn ``oui.json`` nicht gefunden wird --
dann liefert JEDER Lookup ``""``. Das ist ein Fund vom Typ "stiller Fallback"
(Finding-S3-Familie), liegt aber im gewrappten Altcode, nicht im Adapter. Der
Adapter macht den Vertrag ehrlich: ``""`` heisst hier ausdruecklich "OUI nicht
in der DB" UND deckt den Altcode-Leerfall mit ab. Ob die DB ueberhaupt geladen
ist, gehoert -- wenn ueberhaupt -- in einen kuenftigen Startup-Health-Check, NICHT
in den Hot-Path jedes Lookups. Bis dahin als bewusst belassen dokumentiert.
"""

from modules.vendor import lookup_vendor


class VendorLookupAdapter:
    """Erfuellt das ``VendorLookupPort``-Protocol strukturell (sync OUI-Lookup)."""

    def lookup(self, mac: str) -> str:
        """Hersteller zur OUI von ``mac``, oder ``""`` wenn nicht in der DB.

        Reiner In-Memory-Lookup ohne I/O. ``""`` (unbekannte/leere MAC oder OUI
        nicht in der DB) ist ein legitimer Zustand, kein Fehler.
        """
        # ``str(...)``: ``modules`` ist untypisiert (mypy ``follow_imports=skip``),
        # der Vertrag garantiert hier ``str`` -- der Adapter macht das explizit.
        return str(lookup_vendor(mac))
