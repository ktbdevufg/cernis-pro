"""Linux-Adapter fuer ``ProcessProvider`` (P.3, Prozess-Sicht ueber psutil/``/proc``).

Erfuellt den ``ProcessProvider`` strukturell: ``list_processes`` liefert die aktuelle
Prozess-Sicht als rohe ``domain.process.ProcessInfo``-Liste. Die Kernel/Userland-
Klassifikation (``classify_kind``) und der Baum-Aufbau (``build_process_tree``) liegen
in der Domaene -- der Adapter liefert nur die flache Prozessliste.

Schablone ``infrastructure/traffic_linux.py`` / ``interfaces_linux.py``:

* ``list_processes`` ist ``async`` und kapselt das blockierende psutil/``/proc``-I/O
  ueber ``run_in_executor``, der Event-Loop bleibt frei.
* Der synchrone Kern (``_list_processes_sync``) und der reine Mapping-Helfer
  (``_to_process_info``) liegen ausserhalb der Klasse, sind damit ohne Adapter-Instanz
  testbar.

ROOTLESS-REALITAET (Vision 4.2): ``psutil.process_iter`` wirft OHNE Root NICHT --
fremde Prozesse sind als ``pid``/``name`` sichtbar, aber die Detailfelder
(``owner``/``status``/``create_time``/``cmdline``) werfen ``psutil.AccessDenied``. Diese
Felder werden dann ehrlich ``None`` bzw. leer gesetzt, der Prozess aber NICHT
weggelassen -- das ist die "nicht lesbar / benoetigt Root"-Luecke, die die Domaene
(``classify_kind``/``build_process_tree``) traegt. Kein erfundener Wert, kein Wegwerfen.

SCOPE (CLAUDE.md "Nur Linux x64"): psutil ist plattformneutral, ``/proc`` ist Linux;
der Plattform-Riegel sitzt im Rechte-Adapter (``process_permission.py``).
``list_processes`` selbst laeuft ueberall, wo psutil laeuft.

Self-contained stdlib + psutil -- kein ``modules``-Import (import-linter-Contract
"neue Ringe importieren NICHT modules" bleibt unberuehrt).
"""

import asyncio
from collections.abc import Callable
from typing import Any

import psutil

from domain.process import ProcessInfo


def _safe[T](getter: Callable[[], T], default: T) -> T:
    """Liest ein psutil-Feld defensiv; jeder ``psutil.Error`` -> ``default`` -- wirft NIE.

    Ein fremder Prozess wirft beim Lesen seiner Detailfelder ``psutil.AccessDenied``,
    ein verschwindender ``psutil.NoSuchProcess``, ein Zombie ``psutil.ZombieProcess`` --
    alle drei sind KEIN Fehler des Pfads, sondern bedeuten "dieses Feld ist nicht
    lesbar" -> ``default`` (``None`` bzw. Fallback). So bleibt der Prozess in der Liste
    (nur mit ehrlichen Luecken), statt verworfen zu werden.
    """
    try:
        return getter()
    except psutil.Error:
        return default


def _to_process_info(proc: Any) -> ProcessInfo:
    """psutil-``Process`` -> ``ProcessInfo`` mit der ROOTLESS-Naht -- reiner Helfer.

    ``pid`` ist immer da. Jedes weitere Feld wird einzeln ueber ``_safe`` gelesen und
    faellt bei ``psutil.Error`` ehrlich auf ``None`` (bzw. ``""``/``()``) zurueck --
    NICHT den ganzen Prozess wegwerfen, NICHT erfinden:

    * ``name`` -- Fallback ``""`` (NIE ``None`` -- domain-Vertrag).
    * ``ppid`` -- sonst ``None``.
    * ``owner`` (``username()``) -- sonst ``None``.
    * ``status`` -- sonst ``None``.
    * ``create_time`` -- sonst ``None``.
    * ``cmdline`` -- ``tuple(...)``, sonst ``()`` (leer = nicht lesbar, z. B. Kernel-Thread).

    psutil ist untypisiert (kein py.typed): die ``Any``-Rueckgaben werden explizit
    gecastet (``str``/``int``/``float``), wie ``traffic_linux._resolve_app_name``.
    """
    name = _safe(lambda: str(proc.name()), "")
    ppid = _safe(lambda: int(proc.ppid()), None)
    owner = _safe(lambda: str(proc.username()), None)
    status = _safe(lambda: str(proc.status()), None)
    create_time = _safe(lambda: float(proc.create_time()), None)
    empty_cmdline: tuple[str, ...] = ()
    cmdline = _safe(lambda: tuple(str(arg) for arg in proc.cmdline()), empty_cmdline)
    return ProcessInfo(
        pid=int(proc.pid),
        ppid=ppid,
        name=name,
        owner=owner,
        status=status,
        create_time=create_time,
        cmdline=cmdline,
    )


class PsutilProcessAdapter:
    """Erfuellt das ``ProcessProvider``-Protocol (Executor-Wrapper, psutil/``/proc``)."""

    async def list_processes(self) -> list[ProcessInfo]:
        """Stufe 1: aktuelle Prozess-Sicht als rohe ``ProcessInfo``-Liste.

        Blockierendes psutil/``/proc``-I/O -> ``run_in_executor`` (Loop bleibt frei).
        Keine Prozesse -> ``[]`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._list_processes_sync)

    def _list_processes_sync(self) -> list[ProcessInfo]:
        """Synchroner Prozess-Kern (laeuft im Executor-Thread).

        ``psutil.process_iter()`` -> je Prozess ein ``ProcessInfo`` ueber den reinen
        Helfer ``_to_process_info`` (rootless-Naht: nicht lesbare Felder ehrlich
        ``None``/leer). Ein Prozess, der WAEHREND der Iteration verschwindet, wirft
        ``NoSuchProcess`` -> defensiv uebersprungen (kein Abbruch der ganzen Liste).
        """
        result: list[ProcessInfo] = []
        for proc in psutil.process_iter():
            try:
                result.append(_to_process_info(proc))
            except psutil.NoSuchProcess:
                continue  # Prozess waehrend der Iteration verschwunden -- ueberspringen
        return result
