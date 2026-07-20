"""macOS-Adapter fuer PerProcessTrafficProvider und TrafficPermissionPort.

Stufe 1 via psutil.process_iter() + per-PID net_connections() (rootless).
Stufe 2 nicht verfuegbar auf macOS (kein ss/sock_diag) -> [].
"""

from __future__ import annotations

import asyncio
import socket

import psutil

from domain.traffic import (
    Connection,
    ConnSample,
    Endpoint,
    L4Protocol,
    TrafficPermissionResult,
    TrafficPermissionState,
    normalize_status,
)

# Begruendung der Nichtverfuegbarkeit. Benennt WAS fehlt, WARUM es fehlt und WAS
# trotzdem funktioniert -- und enthaelt bewusst KEINE Handlungsaufforderung: die
# Messung fehlt hier nicht wegen fehlender Rechte, sondern weil macOS sie nicht
# anbietet. Ein Rat, das Backend mit erhoehten Rechten zu starten (wie ihn der
# Linux-Adapter gibt), waere hier falsch UND wirkungslos -- root aendert daran
# nichts, und das Projekt eskaliert grundsaetzlich keine Rechte.
_NOT_APPLICABLE_REASON = (
    "Der Durchsatz je Programm (Stufe 2) laesst sich auf macOS nicht messen: das "
    "System stellt dafuer keine Schnittstelle bereit (unter Linux liefert sie "
    "sock_diag). Welche Programme mit welchen Gegenstellen sprechen (Stufe 1), "
    "wird vollstaendig angezeigt."
)

_L4_BY_SOCKET_KIND: dict[int, L4Protocol] = {
    int(socket.SOCK_STREAM): "tcp",
    int(socket.SOCK_DGRAM): "udp",
}


def _endpoint(addr: object) -> Endpoint | None:
    if not addr:
        return None
    return Endpoint(ip=addr.ip, port=addr.port)  # type: ignore[attr-defined]


def _list_connections_sync() -> list[Connection]:
    """Stufe 1 via process_iter + per-PID net_connections (rootless auf macOS)."""
    result: list[Connection] = []
    seen: set[tuple[object, object, object, object, object]] = set()
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                app_name: str | None = proc.info["name"] or None
                pid: int | None = proc.info["pid"]
                for conn in proc.net_connections(kind="inet"):
                    l4 = _L4_BY_SOCKET_KIND.get(int(conn.type))
                    if l4 is None:
                        continue
                    local = _endpoint(conn.laddr)
                    if local is None:
                        continue
                    remote = _endpoint(conn.raddr)
                    key = (
                        l4,
                        local.ip,
                        local.port,
                        remote.ip if remote else None,
                        remote.port if remote else None,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    result.append(
                        Connection(
                            l4=l4,
                            status=normalize_status(conn.status),
                            local=local,
                            remote=remote,
                            pid=pid,
                            app_name=app_name,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except psutil.AccessDenied:
        pass
    return result


class PsutilTrafficAdapter:
    """Erfuellt PerProcessTrafficProvider-Protocol (macOS, rootless Stufe 1)."""

    async def list_connections(self) -> list[Connection]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _list_connections_sync)

    async def sample_throughput(self) -> list[ConnSample]:
        """Stufe 2 nicht verfuegbar auf macOS -> []."""
        return []


class TrafficPermissionAdapter:
    """Erfuellt TrafficPermissionPort-Protocol (macOS)."""

    def is_available(self) -> bool:
        """True -- Stufe 1 laeuft rootless auf macOS."""
        return True

    def check_permission(self) -> str | None:
        """Stufe 2 nicht verfuegbar auf macOS (kein ss/sock_diag) -- mit Begruendung.

        Die schmale Text-Naht (bestehende Wire-Form ``error``). Dass es sich um eine
        PLATTFORMGRENZE und nicht um ein Rechteproblem handelt, sagt der Zustand aus
        ``permission_state`` -- nicht dieser Text.
        """
        return _NOT_APPLICABLE_REASON

    def permission_state(self) -> TrafficPermissionResult:
        """Immer ``NOT_APPLICABLE`` mit Begruendung -- hier gibt es diese Messung nicht.

        Bewusst NICHT ``NEEDS_PRIVILEGES``: es fehlen keine Rechte, die man erlangen
        koennte. macOS bietet kein ``sock_diag``-Aequivalent, also gibt es auf dieser
        Plattform nichts einzurichten und nichts zu eskalieren. Die Oberflaeche kann
        den Unterschied damit ehrlich zeigen, statt einen wirkungslosen Rat zu geben.
        """
        return TrafficPermissionResult(
            state=TrafficPermissionState.NOT_APPLICABLE, reason=_NOT_APPLICABLE_REASON
        )
