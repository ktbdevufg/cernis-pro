"""Adapter fuer ``PortScannerPort`` -- Wrapper um ``modules.portscan``.

Zwei Modi, ueber den ``mode``-Parameter des Ports gewaehlt, beide async-Vertrag:

* ``"socket"`` -> ``modules.scan_ports_socket`` ist bereits ``async`` (eigener
  ``asyncio.Semaphore`` + ``open_connection`` pro Port) -- direkt awaiten.
* ``"nmap"`` -> ``modules.scan_with_nmap`` ist SYNCHRON (blockierender
  ``subprocess``-Aufruf des externen ``nmap``-Binaries) -- ueber
  ``run_in_executor`` kapseln, damit der Event-Loop nicht blockiert. Die
  Port-Methode bleibt ``async`` (Muster wie ``smb_info`` in S.4b).

Beide ``modules``-Funktionen geben ein ``HostPortScan`` mit einer Liste von
``PortResult`` zurueck; der Adapter mappt verlustfrei auf ``tuple``/``list`` von
domaenenreinen ``PortInfo`` (``port``, ``state``, ``service``) -- keine
Fremdtypen (``HostPortScan``/``PortResult``) wandern in die Domaene.

Sicherheits-/Altmuster-Befunde (geprueft):

* KEINE Injection in ``scan_with_nmap``: ``subprocess.run([...], ...)`` mit einer
  ARGUMENT-LISTE und OHNE ``shell=True`` -- ``ip`` und die Port-Spec sind
  einzelne Listenelemente, kein interpolierter Shell-String. (Anders als die
  ``osascript``-Faelle S2, hier nicht beruehrt.)
* ``port_spec`` als String: Der Port liefert ``ports: Sequence[int]``
  (typsicher). Der Adapter baut daraus die nmap-Port-Spec per
  ``",".join(str(p) ...)`` -- aus ints kann kein Injection-String entstehen.
  Der Altcode-Default-Spec (``"T:1-1024,..."``) wird bewusst NICHT durchgereicht;
  gescannt werden genau die vom Use-Case gewaehlten Ports.
* ``ip``-Validierung: bewusst NICHT im Adapter. Die Formatpruefung liegt
  vertraglich in ``ScanConfig`` (domain) bzw. im Use-Case (S.5); der Adapter
  verlaesst sich darauf (konsistent zu ``host_discovery``/``hostname_resolver``).

Bewusste Abweichung vom v1-Verhalten (Finding S3, CLAUDE.md "keine stillen
Fallbacks"):

* v1 ``scan_with_nmap`` schluckt JEDEN nmap-Fehler (Binary nicht gefunden,
  Timeout, sonstiger Fehler) und gibt eine LEERE Port-Liste zurueck -- der
  Fehler steht nur im ``scan_method``-Feld (``"nmap_not_found"`` /
  ``"nmap_timeout"`` / ``"nmap_error"``). Nach aussen ununterscheidbar von
  "keine offenen Ports". Das ist ein verdecktes Scheitern.
* v2: Der Adapter prueft ``scan_method`` des Rueckgabewerts und wirft bei einem
  dieser drei Fehler-Sentinel einen ``NmapScanError`` (mit ``ip`` + Sentinel,
  diagnostizierbar). Eine LEERE Liste bedeutet damit garantiert "Scan
  erfolgreich, keine offenen Ports gefunden" -- der vertragliche Leer-Zustand,
  KEIN Fehler. Saubere Trennung: Exception = Scan gescheitert, ``[]`` = Erfolg
  ohne Funde.
* Der ``"socket"``-Modus kennt keinen solchen Sentinel: ``scan_ports_socket``
  gibt nur offene Ports zurueck, ``[]`` heisst dort schlicht "keine offenen
  Ports". Daher dort kein Sentinel-Check.
"""

import asyncio
from collections.abc import Sequence
from typing import Any

from domain.scanning import PortInfo
from modules.portscan import scan_ports_socket, scan_with_nmap

# nmap-Fehler-Sentinel aus ``scan_method`` (v1 ``scan_with_nmap``): kein offener
# Port, sondern ein gescheiterter Scan. Der Erfolgsfall heisst ``"nmap"``.
_NMAP_ERROR_METHODS = frozenset({"nmap_not_found", "nmap_timeout", "nmap_error"})


class NmapScanError(Exception):
    """Der ``nmap``-Scan eines Hosts ist gescheitert (Binary, Timeout, Fehler).

    Ersetzt den stillen leeren Rueckgabewert des Altcodes (Finding S3): ein
    fehlgeschlagener nmap-Lauf ist ein Fehler MIT ``ip``-Bezug, kein als "keine
    offenen Ports" getarntes Scheitern (Muster wie ``CorruptScanError`` aus S.4a).
    """

    def __init__(self, ip: str, scan_method: str) -> None:
        self.ip = ip
        self.scan_method = scan_method
        super().__init__(f"nmap-Scan von {ip!r} gescheitert: {scan_method}")


def _to_port_infos(raw: Any) -> list[PortInfo]:
    """``modules.HostPortScan`` -> ``list[PortInfo]`` (verlustfrei, domaenenrein).

    ``raw`` ist ``Any`` -- ``modules`` ist untypisiert (mypy ``follow_imports=
    skip``); der Adapter liest die bekannten Felder (``port``, ``state``,
    ``service``) jedes ``PortResult`` direkt und mappt sie explizit auf
    ``PortInfo``. ``banner`` (v1-Feld) gibt es im Domaenenmodell nicht und wird
    bewusst nicht uebernommen.
    """
    return [
        PortInfo(port=int(p.port), state=str(p.state), service=str(p.service)) for p in raw.ports
    ]


class PortScannerAdapter:
    """Erfuellt das ``PortScannerPort``-Protocol strukturell (socket + nmap)."""

    async def scan(
        self,
        ip: str,
        ports: Sequence[int],
        mode: str,
        timeout: float,
        max_concurrent: int,
    ) -> list[PortInfo]:
        """Scannt ``ports`` auf ``ip`` und liefert die offenen als ``PortInfo``.

        ``mode == "nmap"`` -> blockierendes Binary ueber ``run_in_executor``,
        Fehler werden zu ``NmapScanError`` (siehe Modul-Docstring, Finding S3).
        Jeder andere ``mode`` (insbesondere ``"socket"``) -> async-Socket-Scan.
        Keine offenen Ports -> ``[]``, niemals ``None``.
        """
        if mode == "nmap":
            loop = asyncio.get_running_loop()
            # Port-Spec aus ints gebaut -- injektionsfrei (siehe Docstring).
            port_spec = ",".join(str(p) for p in ports)
            raw = await loop.run_in_executor(None, scan_with_nmap, ip, port_spec)
            scan_method = str(raw.scan_method)
            if scan_method in _NMAP_ERROR_METHODS:
                # v2: kein stiller leerer Rueckfall -- gescheiterter Scan ist ein Fehler.
                raise NmapScanError(ip, scan_method)
            return _to_port_infos(raw)

        # socket-Modus (Default): ``scan_ports_socket`` ist bereits async.
        raw = await scan_ports_socket(
            ip, list(ports), max_concurrent=max_concurrent, timeout=timeout
        )
        return _to_port_infos(raw)
