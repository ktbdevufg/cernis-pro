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

Block 1b (Tool-/Paketmanager-Erkennung) -- zwei synchrone Erkennungs-Vertraege (Muster
``TraceroutePermissionPort``: schnelle, lokale which-Pruefungen ohne Loop-I/O):

* ``ToolDetector`` -- prueft, ob ein EINZELNES Binary nutzbar ist (which-basiert; ob das
  ueber ``shutil.which`` oder anders geschieht, ist Adapter-Sache).
* ``PackageManagerDetector`` -- welcher bekannte Paketmanager im PATH liegt; ``None`` wenn
  keiner. Die Erkennungs-Reihenfolge (welcher gewinnt) legt der Adapter fest, nicht der
  Port -- der Vertrag verlangt nur "der erste gefundene".

Block 2a (Banner-Grabbing) -- ein async DATEN-Vertrag (Muster ``TracerouteRunner``):

* ``BannerGrabber`` -- die Banner-DATEN-Quelle. ``grab`` klopft EINMAL an einen Port und
  liest die Begruessung. ``async`` (blockierendes Socket-I/O im Adapter ueber asyncio
  gekapselt, Muster ``TracerouteRunner``). BEWUSST KEIN Rechte-Port: Banner-Grabbing ist
  ein gewoehnlicher TCP-Connect und braucht keine besonderen Rechte (kein Root-Thema).

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

from domain.diagnostics import (
    BannerResult,
    DnsRecordType,
    DnsResult,
    PackageManager,
    TracerouteResult,
)


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


class ToolDetector(Protocol):
    """Erkennungs-Vertrag (1b): ist ein einzelnes System-Binary nutzbar? (which-basiert)."""

    def is_available(self, tool: str) -> bool:
        """``True``, wenn das Binary ``tool`` nutzbar (im PATH) ist, sonst ``False``.

        Reiner Verfuegbarkeits-Check eines EINZELNEN Binaries -- ob ueber ``shutil.which``
        oder anders, ist Adapter-Sache. Schnelle lokale Pruefung, daher synchron (Muster
        ``TraceroutePermissionPort.is_available``).
        """
        ...


class BannerGrabber(Protocol):
    """Daten-Quelle der diagnostics-Domaene (2a): TCP-Banner eines Ports lesen."""

    async def grab(self, target: str, port: int) -> BannerResult:
        """Klopft EINMAL an ``target:port`` und liest die Begruessung -> ``BannerResult``.

        Bestimmt ueber ``domain.probe_for_port`` die Methode (``passive`` -- kurz lauschen,
        der Dienst gruesst selbst; ``http_head`` -- EINE minimale HTTP-HEAD-Anfrage senden)
        und liest die Begruessungszeile bzw. den Server-Header. Ehrliche Semantik (kein
        erfundener Banner): ``state`` benennt ``ok``/``no_banner``/``closed``/``filtered``,
        ``banner`` ist NUR bei ``ok`` nicht-``None``.

        Blockierendes Socket-I/O im Adapter; ueber asyncio gekapselt (Muster
        ``TracerouteRunner``), die Methode bleibt ``async``. KEIN Rechte-Port: ein
        gewoehnlicher TCP-Connect braucht keine besonderen Rechte. SICHERHEITS-GRENZE: der
        Adapter sendet NIE mehr als die eine minimale Standard-Anfrage (keine
        konfigurierbaren Payloads) -- Banner-Grabbing bleibt Diagnose, kein Byte-Sender.
        """
        ...


class PackageManagerDetector(Protocol):
    """Erkennungs-Vertrag (1b): welcher bekannte Paketmanager liegt im PATH?"""

    def detect(self) -> PackageManager | None:
        """Der erste gefundene bekannte Paketmanager, sonst ``None``.

        ``None`` heisst "kein bekannter Paketmanager im PATH" -- dann liefert die Domaene
        ehrlich keinen Install-Befehl (KEIN Raten). Die Erkennungs-Reihenfolge (welcher
        Manager gewinnt, wenn mehrere da sind) legt der Adapter fest, nicht dieser Vertrag.
        Schnelle lokale which-Pruefung, daher synchron.
        """
        ...
