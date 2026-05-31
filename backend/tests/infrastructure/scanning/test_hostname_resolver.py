"""Tests fuer ``HostnameResolverAdapter`` -- gemockte ``modules.resolver``.

Getestet: (1) Port-Konformitaet, (2) ``resolve`` awaitet die bereits-async
``resolve_hostname`` und reicht Argumente + Ergebnis durch, (3) ``smb_info``
treibt die SYNCHRONE ``get_smb_info`` ueber ``run_in_executor`` (das Ergebnis-Tupel
kommt korrekt heraus, der Aufruf landet im Default-Executor, nicht im Loop),
(4) die vom Vertrag vorgesehenen Leer-Zustaende (``""`` / ``("", "")``).

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio`` -- nicht
installiert, wie in S.3). Gemockt wird am IMPORT-ORT IM ADAPTER-MODUL.
"""

import asyncio
import threading

import pytest

from infrastructure.scanning import hostname_resolver
from infrastructure.scanning.hostname_resolver import HostnameResolverAdapter
from ports.scanning import HostnameResolverPort


def test_conforms_to_hostname_resolver_protocol() -> None:
    _: HostnameResolverPort = HostnameResolverAdapter()


def test_resolve_awaits_and_passes_args(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    async def fake_resolve(ip: str, timeout: float) -> str:
        seen["ip"] = ip
        seen["timeout"] = timeout
        return "host.local"

    monkeypatch.setattr(hostname_resolver, "resolve_hostname", fake_resolve)
    result = asyncio.run(HostnameResolverAdapter().resolve("10.0.0.2", 2.5))
    assert result == "host.local"
    assert seen == {"ip": "10.0.0.2", "timeout": 2.5}


def test_resolve_unresolvable_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(ip: str, timeout: float) -> str:
        return ""

    monkeypatch.setattr(hostname_resolver, "resolve_hostname", fake_resolve)
    assert asyncio.run(HostnameResolverAdapter().resolve("10.0.0.2", 1.0)) == ""


def test_smb_info_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Beweis, dass der blockierende Aufruf NICHT im Event-Loop-Thread laeuft:
    # der Fake merkt sich seinen Thread; er muss vom Haupt-(Loop-)Thread abweichen.
    call_thread: dict[str, int] = {}

    def fake_smb(ip: str) -> tuple[str, str]:
        call_thread["tid"] = threading.get_ident()
        return ("NBNAME", "WORKGROUP")

    monkeypatch.setattr(hostname_resolver, "get_smb_info", fake_smb)

    async def _run() -> tuple[str, str]:
        loop_tid = threading.get_ident()
        result = await HostnameResolverAdapter().smb_info("10.0.0.2")
        assert call_thread["tid"] != loop_tid  # im Executor, nicht im Loop
        return result

    assert asyncio.run(_run()) == ("NBNAME", "WORKGROUP")


def test_smb_info_unknown_returns_empty_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hostname_resolver, "get_smb_info", lambda ip: ("", ""))
    assert asyncio.run(HostnameResolverAdapter().smb_info("10.0.0.2")) == ("", "")
