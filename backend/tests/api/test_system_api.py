"""End-to-end-Tests der System-/Glue-API (v2, ADR-0004 P.1) gegen app.py via TestClient.

Deckt die vier additiven Glue-Routen ab, die den Einstiegspunkt-Wechsel
main:app -> app:app schliessen. Die infrastruktur-nahen Provider (system_info,
interfaces, url_opener) werden via ``dependency_overrides`` durch Test-Doubles
ersetzt -- kein echter Browser, kein echtes ``ip``-Tooling, deterministisches
``nmap``/Deps-Probing. ``/api/status`` laeuft gegen die echte Verdrahtung (Version).
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.system import (
    provide_system_info,
    provide_url_opener,
)
from app import create_app
from infrastructure.config import APP_VERSION, AppConfig, display_version


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


def test_status_liefert_200_und_version(app: FastAPI) -> None:
    """``/api/status`` ist die Tauri-Ready-Probe: HTTP 200 + ``{status, version}``."""
    with TestClient(app) as client:
        response = client.get("/api/status")
    assert response.status_code == 200
    # ``/api/status`` liefert die ANZEIGE-Form (``display_version``): das ``+`` der
    # internen ``APP_VERSION`` wird zum Bindestrich (``2.0.0+macos.<sha>`` ->
    # ``2.0.0-macos.<sha>``), im Dev unveraendert ``2.0.0``.
    assert response.json() == {"status": "ok", "version": display_version(APP_VERSION)}


def test_open_url_oeffnet_http_und_https(app: FastAPI) -> None:
    """Gueltige http/https-URL -> ``{ok: True}`` UND der Opener wird gerufen (Spy)."""
    opened: list[str] = []
    app.dependency_overrides[provide_url_opener] = lambda: opened.append

    with TestClient(app) as client:
        for url in ("http://example.com", "https://example.com/path"):
            response = client.post("/api/open-url", json={"url": url})
            assert response.status_code == 200
            assert response.json() == {"ok": True}

    assert opened == ["http://example.com", "https://example.com/path"]


def test_open_url_weist_fremdes_schema_ab(app: FastAPI) -> None:
    """Nicht-http/https-Schema -> ``{ok: False, error}`` UND der Opener wird NICHT gerufen.

    Das ist der kritische Guard (Schutz vor URL-/Command-Injection): ``file:``/
    ``javascript:`` etc. duerfen den Browser-Opener nie erreichen.
    """
    opened: list[str] = []
    app.dependency_overrides[provide_url_opener] = lambda: opened.append

    with TestClient(app) as client:
        for url in ("file:///etc/passwd", "javascript:alert(1)", "ftp://host", ""):
            response = client.post("/api/open-url", json={"url": url})
            assert response.status_code == 200
            assert response.json() == {"ok": False, "error": "Invalid URL"}

    assert opened == []  # Opener NIE gerufen.


def test_system_info_liefert_reduzierten_report(app: FastAPI) -> None:
    """``/api/system/info`` liefert die erwarteten (reduzierten) Keys.

    Der Provider wird gemockt (statt echtem shutil.which/importlib) -- der Test
    prueft die Wire-Form, nicht das reale Host-Probing.
    """
    fake_info: dict[str, Any] = {"version": APP_VERSION, "nmap": True, "scapy": False}
    app.dependency_overrides[provide_system_info] = lambda: lambda: fake_info

    with TestClient(app) as client:
        response = client.get("/api/system/info")
    assert response.status_code == 200
    body = response.json()
    assert body == fake_info
    # Die mit main.py sterbenden Quer-Deps tauchen NICHT auf.
    for dead in ("pysnmp", "reportlab", "fritzconnection", "dnspython"):
        assert dead not in body
