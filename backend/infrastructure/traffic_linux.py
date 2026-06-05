"""Linux-Adapter fuer ``PerProcessTrafficProvider`` (T.3, Stufe 1 ueber psutil).

Erfuellt den ``PerProcessTrafficProvider`` strukturell: ``list_connections`` liefert
die aktuelle Verbindungssicht als rohe ``domain.traffic.Connection`` (Stufe 1, ohne
Durchsatz -- ``bytes_*``/``*_rate_bps`` bleiben ``None``). Die App-Buendelung macht
der Use-Case ``ListAppTraffic`` ueber ``aggregate_by_app`` -- der Adapter liefert nur
die flache Verbindungsliste.

Schablone ``infrastructure/interfaces_linux.py``:

* ``list_connections`` ist ``async`` und kapselt das blockierende
  ``psutil.net_connections``-I/O ueber ``run_in_executor``, der Event-Loop bleibt frei.
* Der synchrone Kern (``_list_connections_sync``) und die reinen Mapping-Helfer
  liegen ausserhalb der Klasse, sind damit ohne Adapter-Instanz testbar.

ROOTLESS-REALITAET (Vision 4.2): ``psutil.net_connections`` wirft OHNE Root NICHT,
es zeigt nur weniger -- fremde Verbindungen erscheinen mit ``pid=None``. Diese werden
NICHT weggelassen: der Adapter setzt ``app_name=None``, und ``aggregate_by_app``
buendelt sie in die ehrliche None-Gruppe ("nicht zuordenbar / benoetigt Root").

SCOPE (CLAUDE.md "Nur Linux x64"): psutil ist plattformuebergreifend, aber die
v2-Stufe-2-Quelle (``sock_diag``) ist Linux. Stufe 1 hier ist plattformneutral; der
Plattform-Riegel sitzt im Rechte-Adapter (``traffic_permission.py``).

Stufe 2 (``sample_throughput``) ist hier bewusst NICHT implementiert -- der Port
verlangt die Methode, aber der Durchsatz (sock_diag) folgt in T.4. Ein ehrlicher
``NotImplementedError`` statt eines leeren Stubs (kein stiller Fallback, S3).

Self-contained stdlib + psutil -- kein ``modules``-Import (import-linter-Contract
"neue Ringe importieren NICHT modules" bleibt unberuehrt).
"""

import asyncio
import socket

import psutil

from domain.traffic import Connection, ConnSample, Endpoint, L4Protocol, normalize_status

# psutil-``SocketKind`` -> Domaenen-L4. NUR TCP/UDP werden aufgenommen; andere
# Socket-Typen (RAW/SEQPACKET o. Ae.) sind fuer die Per-App-Sicht uninteressant und
# werden im sync-Kern uebersprungen (kein "tcp"-Default-Raten, kein Verwerfen mit
# Fehler -- sie gehoeren schlicht nicht in diese Domaene).
_L4_BY_SOCKET_KIND: dict[int, L4Protocol] = {
    int(socket.SOCK_STREAM): "tcp",
    int(socket.SOCK_DGRAM): "udp",
}


def _resolve_app_name(pid: int) -> str | None:
    """PID -> Prozessname; defensiv (psutil-Fehler -> ``None``, wirft NIE).

    Ein Prozess kann zwischen ``net_connections`` und diesem Lookup verschwinden
    (``NoSuchProcess``) oder fuer den User nicht lesbar sein (``AccessDenied``) --
    beides ist KEIN Fehler, sondern bedeutet "nicht (mehr) zuordenbar" -> ``None``.
    ``aggregate_by_app`` buendelt solche Verbindungen in die None-Gruppe.
    """
    try:
        # psutil ist untypisiert (kein py.typed); name() ist Any -> explizit str.
        return str(psutil.Process(pid).name())
    except psutil.Error:
        return None


def _endpoint(addr: object) -> Endpoint | None:
    """psutil-``addr(ip, port)`` -> ``Endpoint``; leeres/abwesendes ``addr`` -> ``None``.

    ``raddr`` ist bei LISTEN/verbindungslos ``()`` (falsy) -- das wird zu ``None``
    (ehrliche Abwesenheit, kein leeres ``Endpoint``-Sentinel, Domaenen-Vertrag).
    """
    if not addr:
        return None
    return Endpoint(ip=addr.ip, port=addr.port)  # type: ignore[attr-defined]


class PsutilTrafficAdapter:
    """Erfuellt das ``PerProcessTrafficProvider``-Protocol (Executor-Wrapper, psutil)."""

    async def list_connections(self) -> list[Connection]:
        """Stufe 1: aktuelle Verbindungen als rohe ``Connection``-Liste.

        Blockierendes ``psutil``-I/O -> ``run_in_executor`` (Loop bleibt frei). Keine
        Verbindungen -> ``[]`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._list_connections_sync)

    def _list_connections_sync(self) -> list[Connection]:
        """Synchroner Verbindungs-Kern (laeuft im Executor-Thread).

        ``psutil.net_connections(kind="inet")`` -> je sconn eine ``Connection``. Nur
        TCP/UDP (``_L4_BY_SOCKET_KIND``); andere Socket-Typen werden uebersprungen.
        ``status`` ueber ``normalize_status``, ``local``/``remote`` ueber
        ``_endpoint``, ``app_name`` ueber ``_resolve_app_name`` (nur bei PID). Die
        Stufe-2-Felder (``bytes_*``/``*_rate_bps``) bleiben ``None`` -- Stufe-1-Sicht.
        """
        result: list[Connection] = []
        for conn in psutil.net_connections(kind="inet"):
            l4 = _L4_BY_SOCKET_KIND.get(int(conn.type))
            if l4 is None:
                continue  # weder TCP noch UDP -- nicht Teil der Per-App-Sicht
            local = _endpoint(conn.laddr)
            if local is None:
                continue  # ohne lokalen Endpunkt keine sinnvolle Verbindung
            app_name = _resolve_app_name(conn.pid) if conn.pid else None
            result.append(
                Connection(
                    l4=l4,
                    status=normalize_status(conn.status),
                    local=local,
                    remote=_endpoint(conn.raddr),
                    pid=conn.pid,
                    app_name=app_name,
                )
            )
        return result

    async def sample_throughput(self) -> list[ConnSample]:
        """Stufe 2 (Durchsatz): NICHT implementiert -- folgt in T.4 (``sock_diag``).

        Ehrlicher ``NotImplementedError`` statt eines leeren Stubs: der Port verlangt
        die Methode, aber die Stufe-2-Byte-Zaehler-Quelle (``sock_diag``) und der
        Polling-Zustand werden erst in T.4 gebaut (kein stiller Fallback, S3).
        """
        raise NotImplementedError("Stufe-2-Durchsatz (sock_diag) folgt in T.4")
