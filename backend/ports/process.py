"""Ports der process-Domaene: Vertraege fuer die Prozess-Sicht + Rechte-Abfrage.

Zwei Vertraege, getrennt nach Belang (Vision 6.1: "eigener Port fuer die
Rechte-Abfrage"):

* ``ProcessProvider`` -- die DATEN-Quelle. ``list_processes`` liefert die aktuelle
  Prozess-Sicht aus ``/proc`` (Stufe 1). Sie ruft blockierendes System-Tooling
  (psutil/Dateisystem) und ist daher ``async`` (Muster
  ``ports.traffic.PerProcessTrafficProvider.list_connections``); der Adapter (P.3)
  kapselt das Blockierende ueber ``run_in_executor``.
* ``ProcessPermissionPort`` -- die RECHTE-Abfrage, bewusst ein eigener Port (S4/S5,
  Vision 4.2/6.1). Synchron wie ``ports.traffic.TrafficPermissionPort``: schnelle,
  lokale Pruefungen ohne Netz-/Loop-I/O.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/capture/interfaces/traffic). Die Vertragspruefung laeuft statisch ueber mypy
und ueber die Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per
``isinstance``.

``ports/`` kennt NUR ``domain/process``-Typen + stdlib/typing. KEIN ``modules/``-
und kein ``infrastructure/``-Import -- import-linter-Contract "ports kennen
hoechstens domain". Import von ``domain`` ist erlaubt (nur die Gegenrichtung ist
verboten).
"""

from typing import Protocol

from domain.process import ProcessInfo


class ProcessProvider(Protocol):
    """Daten-Quelle der process-Domaene: aktuelle Prozess-Sicht aus ``/proc`` (Stufe 1)."""

    async def list_processes(self) -> list[ProcessInfo]:
        """Stufe 1: aktuelle Prozess-Sicht aus ``/proc``.

        Rootless: eigene Prozesse sind voll lesbar; fremde Prozesse erscheinen mit
        None-Feldern (``ppid``/``owner``/``status``/``create_time`` ``None``, ``cmdline``
        leer) und werden NICHT weggelassen -- das ist die ehrliche "nicht lesbar /
        benoetigt Root"-Luecke. Der ``name`` bleibt nie ``None`` (Fallback ``""``, vgl.
        ``domain.process.ProcessInfo``). Keine Prozesse -> ``[]``, niemals ``None``.

        Blockierendes System-Tooling (psutil/Dateisystem) im Adapter; ueber
        ``run_in_executor`` gekapselt, die Methode bleibt ``async``.
        """
        ...


class ProcessPermissionPort(Protocol):
    """Rechte-Abfrage der process-Domaene (eigener Port, S4/S5; synchron wie capture)."""

    def is_available(self) -> bool:
        """``True``, wenn die Prozess-Quelle grundsaetzlich nutzbar ist.

        Reiner Verfuegbarkeits-Check (Plattform/Tooling vorhanden), unabhaengig von
        Berechtigungen -- die prueft ``check_permission``. Schnelle lokale Pruefung,
        daher synchron (Muster ``ports.traffic``/``ports.capture``).
        """
        ...

    def check_permission(self) -> str | None:
        """Prueft die Sicht-Tiefe; ``None`` = volle Sicht, sonst Begruendung+Hinweis.

        ``None`` heisst "volle Sicht" (Root/ausreichende Rechte -- alle Prozessdetails
        lesbar). Ein nicht-leerer String ist die Begruendung samt Handlungs-Hinweis
        (z. B. "Fuer Details fremder Prozesse muss CERNIS PRO als Root gestartet
        werden: <konkreter Befehl>"). KEIN stiller Fallback (ADR 0001/S3): die fehlende
        Berechtigung wird benannt, nicht verschwiegen. Schnelle lokale Pruefung, daher
        synchron (Muster ``ports.traffic.TrafficPermissionPort.check_permission``).
        """
        ...
