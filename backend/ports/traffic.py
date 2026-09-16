"""Ports der traffic-Domaene: Vertraege fuer Per-App-Verbindungen + Rechte-Abfrage.

Zwei Vertraege, getrennt nach Belang (Vision 6.1: "eigener Port fuer die
Rechte-Abfrage"):

* ``PerProcessTrafficProvider`` -- die DATEN-Quelle. ``list_connections`` liefert
  die aktuelle Verbindungssicht (Stufe 1, psutil), ``sample_throughput`` EINEN
  Messpunkt der kumulativen Socket-Byte-Zaehler (Stufe 2, ``sock_diag``). Beide
  rufen blockierendes System-Tooling und sind daher ``async`` (Muster
  ``ports.interfaces.InterfaceDiscoveryPort.discover``); der Adapter (T.3/T.4)
  kapselt das Blockierende ueber ``run_in_executor``.
* ``TrafficPermissionPort`` -- die RECHTE-Abfrage, bewusst ein eigener Port (S4/S5,
  Vision 4.2/6.1). Synchron wie ``ports.capture``'s ``check_permission``/
  ``is_available``: schnelle, lokale Pruefungen ohne Netz-/Loop-I/O. Der Use-Case
  (``CheckTrafficPermission``) sperrt bei fehlendem Recht NUR den Durchsatz-Bereich
  (Stufe 2), nicht die ganze Domaene.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/capture/interfaces). Die Vertragspruefung laeuft statisch ueber mypy und
ueber die Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per
``isinstance``.

``ports/`` kennt NUR ``domain/traffic``-Typen + stdlib/typing. KEIN ``modules/``-
und kein ``infrastructure/``-Import -- import-linter-Contract "ports kennen
hoechstens domain". Import von ``domain`` ist erlaubt (nur die Gegenrichtung ist
verboten).
"""

from typing import Protocol

from domain.traffic import Connection, ConnSample, TrafficPermissionResult


class PerProcessTrafficProvider(Protocol):
    """Daten-Quelle der traffic-Domaene: Verbindungen (Stufe 1) + Durchsatz (Stufe 2)."""

    async def list_connections(self) -> list[Connection]:
        """Stufe 1: aktuelle Netzwerk-Verbindungen mit aufgeloester App (pid/app_name).

        Rootless: nur eigene Prozesse sind zuordenbar -- fremde Verbindungen
        erscheinen mit ``pid=None``/``app_name=None`` (NICHT weggelassen; das ist die
        ehrliche "nicht zuordenbar / benoetigt Root"-Luecke, die der Use-Case ueber
        ``aggregate_by_app`` in die None-Gruppe buendelt). Die Stufe-2-Felder
        ``bytes_*``/``*_rate_bps`` sind hier ``None`` (reine Stufe-1-Sicht ohne
        Durchsatz). Keine Verbindungen -> ``[]``, niemals ``None``.

        Blockierendes System-Tooling (psutil) im Adapter; ueber ``run_in_executor``
        gekapselt, die Methode bleibt ``async``.
        """
        ...

    async def sample_throughput(self) -> list[ConnSample]:
        """Stufe 2: EIN Messpunkt der kumulativen Socket-Byte-Zaehler (``sock_diag``).

        Ein Aufruf = EINE Momentaufnahme (``key``/``bytes_sent``/``bytes_received``/
        ``monotonic_ts`` je Socket). Die Raten-Berechnung aus ZWEI Messpunkten macht
        der Use-Case ueber die Domaene (``match_samples``/``compute_rate``), NICHT der
        Adapter -- der Adapter misst nur. Keine Sockets -> ``[]``, niemals ``None``.

        Blockierendes System-Tooling im Adapter; ueber ``run_in_executor`` gekapselt,
        die Methode bleibt ``async``.
        """
        ...


class TrafficPermissionPort(Protocol):
    """Rechte-Abfrage der traffic-Domaene (eigener Port, S4/S5; synchron wie capture)."""

    def is_available(self) -> bool:
        """``True``, wenn die Traffic-Quelle grundsaetzlich nutzbar ist.

        Reiner Verfuegbarkeits-Check (Plattform/Tooling vorhanden), unabhaengig von
        Berechtigungen -- die prueft ``check_permission``. Schnelle lokale Pruefung,
        daher synchron (Muster ``ports.capture``).
        """
        ...

    def check_permission(self) -> str | None:
        """Prueft die Sicht-Tiefe; ``None`` = volle Sicht, sonst Begruendung+Hinweis.

        ``None`` heisst "volle Sicht" (Root/ausreichende Rechte -- Durchsatz aller
        Apps moeglich). Ein nicht-leerer String ist die Begruendung samt Handlungs-
        Hinweis (z. B. "Fuer den Durchsatz aller Apps muss CERNIS PRO als Root
        gestartet werden: <konkreter Befehl>"). KEIN stiller Fallback (ADR 0001/S3):
        die fehlende Berechtigung wird benannt, nicht verschwiegen. Schnelle lokale
        Pruefung, daher synchron (Muster ``ports.capture.check_permission``).

        Bleibt als schmale Text-Naht erhalten (bestehende Aufrufer/Wire-Form
        ``error``); WELCHER Zustand vorliegt, beantwortet ``permission_state``.
        """
        ...

    def permission_state(self) -> TrafficPermissionResult:
        """Liefert den Rechte-Befund als Domaenenwert (Zustand + Begruendung).

        Beantwortet die Frage, die ``check_permission`` NICHT beantworten kann: ob
        die Durchsatz-Sicht steht (``GRANTED``), ob ihr nur die Rechte fehlen
        (``NEEDS_PRIVILEGES``) oder ob die Plattform sie gar nicht anbietet
        (``NOT_APPLICABLE``). Die beiden letzten Faelle sehen in der reinen
        Text-Naht identisch aus -- der Unterschied ist aber fachlich (behebbar vs.
        nicht behebbar) und darf nicht aus einer Zeichenkette erraten werden
        muessen (Begruendung an ``TrafficPermissionState``).

        Rueckgabe ist ein Domaenenwert, KEINE Wire-Form -- die Projektion nach JSON
        macht der api-Rand. Schnelle lokale Pruefung, daher synchron.
        """
        ...
