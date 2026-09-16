"""Adapter fuer ``MonitorPingerPort`` -- Wrapper um ``modules.monitor._ping_burst``.

``_ping_burst`` ist im Altcode bereits ``async`` (es awaitet ``_ping_once``, das
``asyncio.create_subprocess_exec`` + ``asyncio.wait_for`` nutzt -- vollstaendig
non-blocking). Darum wird es DIREKT geawaitet, KEIN ``run_in_executor`` (das wuerde
eine Coroutine faelschlich in einen Thread werfen) -- gleiches Muster wie
``HostnameResolverAdapter.resolve`` (S.4a: modules-Funktion schon async -> direkt
awaiten). Der ``modules``-Import ist durch die ADR-0007-Erweiterung
``infrastructure.monitoring.** -> modules`` abgedeckt (M.4).

Mapping ``PingResult`` (modules) -> ``PingSample`` (domain), charakterisierungstreu:

* ``target_id`` setzt der Adapter aus ``target.id`` (der Altcode liess es leer und
  der Loop fuellte es nach -- in v2 kennt der Adapter das Target, also direkt).
* ``rtt_ms`` mit dem RTT-Sentinel ``-1.0`` (= "keine RTT") UNVERAENDERT uebernommen
  -- NICHT zu ``None`` normalisiert (M.2-Entscheidung: das ist eine Adapter-Rand-
  Frage, hier bewusst treu, weil ``rtt_history`` den Sentinel persistiert).
* ``loss_pct`` und ``alive`` (= ``alive_count > 0``) wie aggregiert.
* ``timestamp`` aus dem ``PingResult.timestamp`` (Altcode: ``time.time()`` zur
  Erzeugung) uebernommen.

Altmuster-Befund (geprueft, unkritisch): ``_ping_once`` ruft ``ping`` ueber
``asyncio.create_subprocess_exec(*cmd)`` mit einer ARGUMENT-LISTE, OHNE
``shell=True`` -- ``host`` ist ein Argument, kein interpolierter Shell-String. Keine
Injection (≠ die ``osascript``-S2-Faelle). Das ``except Exception: return
(False, -1.0)`` ist der vertragliche "nicht erreichbar"-Zustand, kein verdecktes
Scheitern (kein S3-Umbau).
"""

from domain.monitoring import MonitorTarget, PingSample
from modules.monitor import _ping_burst


class MonitorPingerAdapter:
    """Erfuellt das ``MonitorPingerPort``-Protocol strukturell (modules-Wrapper)."""

    async def ping(self, target: MonitorTarget) -> PingSample:
        """Pingt ``target`` (3er-Burst) und aggregiert zu ``PingSample``.

        ``_ping_burst`` ist bereits async -> direkt awaiten (kein executor). Ein
        nicht erreichbares Target liefert ``PingSample(alive=False, rtt_ms=-1.0,
        ...)`` -- kein Fehler, der Sentinel bleibt erhalten.
        """
        result = await _ping_burst(target.host, target.interface)
        return PingSample(
            target_id=target.id,
            host=target.host,
            alive=bool(result.alive),
            rtt_ms=float(result.rtt_ms),
            loss_pct=float(result.loss_pct),
            timestamp=float(result.timestamp),
        )
