"""Ports der diagnostics-Domaene: Vertraege fuer DNS-Aufloesung + traceroute.

Drei Vertraege, getrennt nach Belang:

* ``DnsResolver`` -- die DNS-DATEN-Quelle. ``resolve`` loest einen Namen fuer eine Menge
  angefragter Eintragsarten auf. Sie ruft blockierendes System-Tooling (``dig``) und ist
  daher ``async`` (Muster ``ports.process.ProcessProvider.list_processes``); der Adapter
  kapselt das Blockierende ueber ``run_in_executor``. BEWUSST KEIN Rechte-Port fuer DNS:
  Namensaufloesung braucht keine besonderen Rechte (kein Root-Thema).
* ``TracerouteRunner`` -- die traceroute-DATEN-Quelle. ``run`` misst den Pfad zum Ziel.
  ``privileged=True`` waehlt die genauere (Root-)Methode, ``False`` die unprivilegierte
  (ungenauere) -- bewusste Nutzerwahl, kein Default-Raten. Auch ``async`` (blockierendes
  ``traceroute``-Binary im Adapter ueber ``run_in_executor``).
* ``TraceroutePermissionPort`` -- die RECHTE-Abfrage fuer traceroute, bewusst ein eigener
  Port (Muster ``ports.process.ProcessPermissionPort``). Synchron: schnelle, lokale
  Pruefungen ohne Netz-/Loop-I/O. Hier bedeutet "volle Rechte" = die genauere
  (privilegierte) Methode ist moeglich; ohne Rechte wird die unprivilegierte Methode
  verwendet (ehrlicher Hinweis, kein stiller Fallback, S3).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/capture/interfaces/traffic/process). Die Vertragspruefung laeuft statisch ueber
mypy und ueber die Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per
``isinstance``.

``ports/`` kennt NUR ``domain/diagnostics``-Typen + stdlib/typing. KEIN ``modules/``-
und kein ``infrastructure/``-Import -- import-linter-Contract "ports kennen hoechstens
domain". Import von ``domain`` ist erlaubt (nur die Gegenrichtung ist verboten).
"""

from collections.abc import Sequence
from typing import Protocol

from domain.diagnostics import DnsRecordType, DnsResult, TracerouteResult


class DnsResolver(Protocol):
    """Daten-Quelle der diagnostics-Domaene: DNS-Aufloesung (kein Rechte-Thema)."""

    async def resolve(self, query: str, types: Sequence[DnsRecordType]) -> DnsResult:
        """Loest ``query`` fuer die angefragten ``types`` auf -> ``DnsResult``.

        Liefert die gefundenen Eintraege gebuendelt als ``DnsResult`` (``query`` +
        angefragte Typen + Eintraege). Keine Antwort (NXDOMAIN/leer) -> ``records`` LEER,
        NICHT ``None`` und KEIN Fehler -- die leere Antwort ist ein gueltiges Ergebnis.
        Ein echter Fehler (fehlendes ``dig``-Binary) ist eine Exception, kein leeres
        Ergebnis.

        Blockierendes System-Tooling (``dig``) im Adapter; ueber ``run_in_executor``
        gekapselt, die Methode bleibt ``async``. KEIN Rechte-Port: Namensaufloesung
        braucht keine besonderen Rechte.
        """
        ...


class TracerouteRunner(Protocol):
    """Daten-Quelle der diagnostics-Domaene: Pfad-Messung zum Ziel (traceroute)."""

    async def run(self, target: str, privileged: bool) -> TracerouteResult:
        """Misst den Pfad zu ``target`` -> ``TracerouteResult``.

        ``privileged=True`` waehlt die genauere (Root-)Methode (z. B. ICMP), ``False`` die
        unprivilegierte UDP-Default-Methode -- bewusste Nutzerwahl, kein Default-Raten.
        Nicht-antwortende Hops erscheinen als Luecke (``address``/``rtt_ms`` ``None``),
        NICHT weggelassen. Kein Hop ermittelbar -> ``hops`` leer (kein Fehler). Ein echter
        Fehler (fehlendes ``traceroute``-Binary) ist eine Exception.

        Blockierendes System-Tooling (``traceroute``) im Adapter; ueber
        ``run_in_executor`` gekapselt, die Methode bleibt ``async``.
        """
        ...


class TraceroutePermissionPort(Protocol):
    """Rechte-Abfrage fuer traceroute (eigener Port; synchron wie process/capture)."""

    def is_available(self) -> bool:
        """``True``, wenn das ``traceroute``-Binary grundsaetzlich nutzbar ist.

        Reiner Verfuegbarkeits-Check (Binary im PATH), unabhaengig von Berechtigungen --
        die prueft ``check_permission``. Schnelle lokale Pruefung, daher synchron (Muster
        ``ports.process.ProcessPermissionPort.is_available``).
        """
        ...

    def check_permission(self) -> str | None:
        """``None`` = privilegierte (genauere) Methode moeglich, sonst Begruendung+Hinweis.

        ``None`` heisst "privilegierte Methode moeglich" (Root) -- die genauere Messung
        ist verfuegbar. Ein nicht-leerer String ist die Begruendung: die genauere Methode
        braucht Root; ohne Root wird die unprivilegierte (ungenauere) Methode verwendet.
        KEIN stiller Fallback (ADR 0001/S3): die fehlende Berechtigung wird benannt, nicht
        verschwiegen. KEIN distro-spezifischer Install-Befehl hier (das ist Block 1b).
        Schnelle lokale Pruefung, daher synchron.
        """
        ...
