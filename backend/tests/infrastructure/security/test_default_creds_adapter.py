"""Tests fuer ``DefaultCredsCheckerAdapter`` (SEC.4) -- v2-Reimpl + Heilung E.4b/E.4c.

AUFLAGE A2 -- die PRAEZISE Trennung als Vertrag:
  * E.4b HTTP: echter Netzfehler -> kein Treffer + Warn-Log ``cred_http_check_error``.
    HTTPError 401 (Cred falsch) = TRAGENDES Negativ -> kein Treffer, KEIN Log.
  * E.4c FTP: Verbindungsfehler -> kein Treffer + Warn-Log ``cred_ftp_check_error``.
    error_perm (Login falsch) = TRAGENDES Negativ -> kein Treffer, KEIN Log.
  * Loop ueberlebt: ein Port wirft, einer trifft -> der Treffer kommt durch.

KEIN echter Login: build_opener + ftplib.FTP gemockt.
"""

import ftplib
import urllib.error
import urllib.request
from typing import Any

import pytest
from structlog.testing import capture_logs

from infrastructure.security import default_creds as dc_mod
from ports.security import CredFinding, PortQuery


class _FakeResponse:
    def __init__(self, code: int) -> None:
        self.code = code


class _FakeOpener:
    def __init__(self, behavior: Any) -> None:
        self._behavior = behavior

    def open(self, req: Any, timeout: float = 3.0) -> Any:
        return self._behavior(req, timeout)


def _patch_http(monkeypatch: pytest.MonkeyPatch, behavior: Any) -> None:
    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener(behavior))


def _patch_ftp(monkeypatch: pytest.MonkeyPatch, fail: Exception | None) -> None:
    class _FakeFTP:
        def connect(self, host: str, port: int, timeout: float = 3.0) -> None:
            return None

        def login(self, user: str = "", passwd: str = "") -> None:
            if fail is not None:
                raise fail

        def quit(self) -> None:
            return None

    monkeypatch.setattr(ftplib, "FTP", _FakeFTP)


# ── Erfolgsfall ───────────────────────────────────────────────


def test_http_basic_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_http(monkeypatch, lambda req, timeout: _FakeResponse(200))
    r = dc_mod._check_http_basic("h", 80, [("admin", "admin")], https=False)
    assert len(r) == 1 and r[0].method == "http_basic" and r[0].note == "HTTP 200"


# ── E.4b: HTTP-Netzfehler -> kein Treffer + Warn-Log ──────────


def test_E4b_network_error_logs_AND_no_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(req: Any, timeout: float) -> Any:
        raise TimeoutError("connect timed out")

    _patch_http(monkeypatch, _boom)
    with capture_logs() as logs:
        r = dc_mod._check_http_basic("h", 80, [("admin", "admin")], https=False)
    assert r == []  # Ergebnis wie SEC.1b-Vorher
    assert any(e["event"] == "cred_http_check_error" for e in logs)  # HEILUNG: geloggt


def test_E4b_http_401_is_tragendes_negativ_NO_log(monkeypatch: pytest.MonkeyPatch) -> None:
    # HTTPError 401 = Cred falsch -> kein Treffer, KEIN Log (sonst Log-Spam pro Scan).
    def _http_401(req: Any, timeout: float) -> Any:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    _patch_http(monkeypatch, _http_401)
    with capture_logs() as logs:
        r = dc_mod._check_http_basic("h", 80, [("admin", "admin")], https=False)
    assert r == []
    assert not any(e["event"] == "cred_http_check_error" for e in logs)


# ── E.4c: FTP-Verbindungsfehler vs. error_perm ────────────────


def test_E4c_connection_error_logs_AND_no_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_ftp(monkeypatch, fail=OSError("connection refused"))
    with capture_logs() as logs:
        r = dc_mod._check_ftp("h", 21)
    assert r == []
    assert any(e["event"] == "cred_ftp_check_error" for e in logs)  # HEILUNG: geloggt


def test_E4c_error_perm_is_tragendes_negativ_NO_log(monkeypatch: pytest.MonkeyPatch) -> None:
    # error_perm = Login falsch -> kein Treffer, KEIN Log.
    _patch_ftp(monkeypatch, fail=ftplib.error_perm("530 Login incorrect"))
    with capture_logs() as logs:
        r = dc_mod._check_ftp("h", 21)
    assert r == []
    assert not any(e["event"] == "cred_ftp_check_error" for e in logs)


def test_ftp_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_ftp(monkeypatch, fail=None)
    r = dc_mod._check_ftp("h", 21)
    assert len(r) == 1 and r[0].method == "ftp" and r[0].username == "anonymous"


# ── Loop ueberlebt: ein Port wirft, einer trifft ─────────────


def test_loop_survives_one_failing_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # _check_http_basic WIRFT fuer Port 80 mitten im Loop (unerwarteter Fehler ausserhalb
    # seiner eigenen Faenge) -> der per-Item-try IN der _check_host_sync-Schleife faengt
    # es + loggt, Port 8080 wird weiter geprueft. Beweist den Loop-Schutz an der
    # richtigen Stelle.
    from infrastructure.security import default_creds as dc_module

    def _fake_basic(
        host: str, port: int, creds: Any, https: bool = False, timeout: float = 3.0
    ) -> list[Any]:
        if port == 80:
            raise RuntimeError("unexpected check error")  # wirft MITTEN im Loop
        return [
            CredFinding(
                host=host,
                port=port,
                service="http",
                username="admin",
                password="admin",
                success=True,
                method="http_basic",
                note="HTTP 200",
            )
        ]

    monkeypatch.setattr(dc_module, "_check_http_basic", _fake_basic)

    with capture_logs() as logs:
        r = dc_module.DefaultCredsCheckerAdapter()._check_host_sync(
            "h", [PortQuery(80, "http"), PortQuery(8080, "http")], vendor=""
        )
    # (a) der GESUNDE Port (8080) trifft konkret.
    assert [f.port for f in r] == [8080]
    # (b) der KAPUTTE (80) ist geloggt + fehlt.
    assert any(e["event"] == "cred_port_check_failed" and e["port"] == 80 for e in logs)
    assert all(f.port != 80 for f in r)


# MUTATIONSPROBE (dokumentiert): zieht man in default_creds.py:_check_host_sync das
# per-Item-try VOR/UM die ``for p``-Schleife (statt drin), killt der RuntimeError bei
# Port 80 die ganze Schleife -> der 8080-Treffer fehlt -> dieser Test wird rot.


# ── Routing + Vendor-Creds ────────────────────────────────────


def test_routing_https_port(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def _behavior(req: Any, timeout: float) -> Any:
        seen.append(req.full_url.startswith("https"))
        raise TimeoutError  # kein Treffer, nur Routing pruefen

    _patch_http(monkeypatch, _behavior)
    # Port 4443 ohne "http"-Substring im service -> https-Zweig (https=True). Jeder der
    # bis zu 8 Versuche nutzt dasselbe Schema -> alle True.
    dc_mod.DefaultCredsCheckerAdapter()._check_host_sync("h", [PortQuery(4443, "")], vendor="")
    assert seen and all(seen)  # https-Schema bei jedem Versuch


def test_vendor_creds_used() -> None:
    creds = dc_mod.get_creds_for_vendor("Ubiquiti Networks")
    assert ("ubnt", "ubnt") in creds
