"""Ports (Vertraege) der maintenance-Domaene -- die MAC-gebundene Vollloeschung.

Ein einziger Vertrag: ``DevicePurgeRepository`` raeumt eine MENGE von Geraeten
samt ALLER MAC-gebundenen Nebendaten in EINER Transaktion ab.

WARUM EIN EIGENER PORT und nicht die vorhandenen Repos (Messung S88-P3, 1.1):
Der bestehende Loeschweg des Werkszustands (``FactoryReset``/``ResetScanData``)
bietet dafuer KEINE Bausteine. Er kennt ausschliesslich ``clear_all()`` je
Repository -- tabellenweit, ohne MAC-Filter. Und selbst wenn jedes Repo ein
``delete_for_macs`` truege, oeffnet jeder Adapter seine EIGENE Connection
(``sqlite3.connect(self._db_path)`` je Aufruf); acht Aufrufe waeren acht
Transaktionen. Genau das ist hier verboten: nur EINE Transaktion haelt Geraet und
Nebendaten zusammen. Darum ein eigener Vertrag, den ein einziger Adapter mit
einer einzigen Connection erfuellt.

``ports/`` kennt nur ``domain/``-Typen + stdlib (import-linter). Der Vertrag ist
bewusst primitiv typisiert (``Iterable[str]`` rein, ``int`` raus) -- er traegt
keine Domaenen-Objekte, weil es hier nichts zu modellieren gibt ausser der Menge
der zu raeumenden Adressen.
"""

from collections.abc import Iterable
from typing import Protocol

__all__ = ["DevicePurgeRepository"]


class DevicePurgeRepository(Protocol):
    """Vollloeschung einer Geraete-MENGE samt aller MAC-gebundenen Nebendaten."""

    def purge_devices(self, macs: Iterable[str]) -> int:
        """Loescht die uebergebenen Geraete VOLLSTAENDIG -- in EINER Transaktion.

        Geraeumt werden die ``devices``-Zeilen, der IP-Verlauf
        (``device_ip_history``) und alle sieben MAC-gebundenen Nebentabellen:
        ``cve_findings``, ``cve_check_state``, ``cve_acknowledgements``,
        ``analysis_acknowledgements``, ``analysis_known_hosts``, ``arp_baseline``
        und ``arp_alerts``.

        ALLES ODER NICHTS: Bricht ein Schritt ab, ist NICHTS geloescht (Rollback).
        Ein halber Bestand -- Geraet weg, Befunde verwaist -- waere schlimmer als
        gar keine Loeschung, weil er sich nicht mehr zuordnen laesst.

        SCHREIBWEISE (gemessen, S88-P3): Die Tabellen fuehren die MAC NICHT
        einheitlich. ``devices`` fuehrt sie kanonisch GROSS (ueber
        ``domain.devices.normalize_mac``), die drei ``cve_*``-Tabellen ebenfalls
        gross (``infrastructure/_cve_mac.py``), aber ``analysis_known_hosts``,
        ``analysis_acknowledgements`` und die beiden ``arp_*``-Tabellen fuehren
        schlicht das, was der Scan liefert -- und der liefert klein. Der Adapter
        vergleicht darum case-insensitiv; ein Vergleich auf Gleichheit liesse die
        Nebendaten nachweislich stehen.

        Idempotent: eine unbekannte MAC ist KEIN Fehler, sie raeumt nur nichts ab
        (Vertrag wie ``DeviceRepository.delete``). Eine leere Menge ist ebenfalls
        kein Fehler und loescht nichts.

        Rueckgabe: die Zahl der tatsaechlich geloeschten ``devices``-Zeilen (nicht
        der Nebendaten-Zeilen). Damit kann der Aufrufer melden, wie viele Geraete
        wirklich gingen -- ohne die Nebentabellen mitzuzaehlen, deren Zeilenzahl
        fuer den Anwender keine Aussage haette.
        """
        ...
