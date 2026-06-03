"""Characterization-Contract der alerting-REST-Endpunkte (Altcode main.py).

Vorbild: test_monitoring_rest_contract -- die Endpunkt-Funktionen werden auf eine
FRISCHE App gehaengt (``add_api_route``, KEINE main-Lifespan), gegen ``main`` (nicht
``app``) importiert, damit der Contract beim Einstiegspunkt-Wechsel (A.6) gueltig bleibt.
Modul-Helfer sind am main-Namespace gemockt; netzwerk-/DB-frei.

Eingefrorene Shapes (AS-IS, 8 Endpunkte):
  GET  /api/alerts/rules          -> list[dict], enabled/notify_* int 0/1
  POST /api/alerts/rules          -> {"ok": True, "id": int}
  PATCH/api/alerts/rules/{id}     -> {"ok": True}; enabled-Wert durchgereicht (int)
  DELETE/api/alerts/rules/{id}    -> {"ok": True}
  GET  /api/alerts/history        -> list[dict]
  GET  /api/alerts/smtp           -> Passwort redigiert als "••••••••"
                                     (8x U+2022), uebrige Felder unveraendert
  PUT  /api/alerts/smtp           -> {"ok": True}; PW verschluesselt, kein Klartext zurueck
  POST /api/alerts/test           -> {"success": bool, "log": [str]}
                                     400 ohne host/to, 200 bei success, 503 sonst

WIRE-VERTRAG (s. test_alerting_storage): enabled/notify_* bleiben int 0/1, NIE bool.
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main

# IST-Shapes der Helfer-Rueckgaben, am main-Namespace gemockt.
_RULE_ROW = {
    "id": 1,
    "name": "Host Down",
    "rule_type": "host_down",
    "target": "any",
    "threshold": 60,
    "notify_email": 0,
    "notify_macos": 1,
    "enabled": 1,
    "last_triggered": 0.0,
}
_HISTORY_ROW = {
    "id": 1,
    "rule_id": 1,
    "rule_name": "Host Down",
    "rule_type": "host_down",
    "target": "192.168.1.1",
    "message": "host down",
    "ts": 1_700_000_000.0,
    "datetime": "2026-06-03 00:00:00",
}


@pytest.fixture
def rest_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Rule-CRUD-Helfer (alerting via Alias am main-Namespace, s. main.py:76-78).
    monkeypatch.setattr(main, "get_alert_rules", lambda: [_RULE_ROW])
    monkeypatch.setattr(main, "add_alert_rule", lambda **kwargs: 7)
    update_seen: dict[str, Any] = {}
    monkeypatch.setattr(
        main, "update_alert_rule", lambda rule_id, **kwargs: update_seen.update(kwargs)
    )
    monkeypatch.setattr(main, "delete_alert_rule", lambda rule_id: None)
    monkeypatch.setattr(main, "get_alert_history", lambda limit=50: [_HISTORY_ROW])

    # SMTP-Settings am main-Namespace; ein In-Memory-Store fuer GET/PUT-Round-trip.
    settings_store: dict[str, Any] = {}
    monkeypatch.setattr(
        main, "get_setting", lambda key, default=None: settings_store.get(key, default)
    )
    monkeypatch.setattr(
        main, "set_setting", lambda key, value: settings_store.__setitem__(key, value)
    )

    # crypto wird in den Endpunkten LAZY importiert (from modules.crypto import ...),
    # haengt also nicht am main-Namespace -> am crypto-Modul mocken.
    from modules import crypto

    monkeypatch.setattr(crypto, "encrypt", lambda plaintext: f"ENC({plaintext})")
    monkeypatch.setattr(crypto, "decrypt", lambda ciphertext: "decrypted-pw")

    # notify_email_with_log ebenfalls lazy importiert -> am alerting-Modul mocken.
    # Default: Erfolg. Einzeltests biegen das pro Fall um.
    from modules import alerting

    monkeypatch.setattr(
        alerting,
        "notify_email_with_log",
        lambda subject, body, smtp_config: {"success": True, "log": ["Email sent successfully!"]},
    )

    fresh = FastAPI()
    fresh.add_api_route("/api/alerts/rules", main.api_alert_rules, methods=["GET"])
    fresh.add_api_route("/api/alerts/rules", main.api_add_alert_rule, methods=["POST"])
    fresh.add_api_route(
        "/api/alerts/rules/{rule_id}", main.api_update_alert_rule, methods=["PATCH"]
    )
    fresh.add_api_route(
        "/api/alerts/rules/{rule_id}", main.api_delete_alert_rule, methods=["DELETE"]
    )
    fresh.add_api_route("/api/alerts/history", main.api_alert_history, methods=["GET"])
    fresh.add_api_route("/api/alerts/smtp", main.api_get_smtp, methods=["GET"])
    fresh.add_api_route("/api/alerts/smtp", main.api_set_smtp, methods=["PUT"])
    fresh.add_api_route("/api/alerts/test", main.api_test_alert, methods=["POST"])

    client = TestClient(fresh, raise_server_exceptions=False)
    # Store + Spy fuer Tests zugaenglich machen.
    client.settings_store = settings_store  # type: ignore[attr-defined]
    client.update_seen = update_seen  # type: ignore[attr-defined]
    return client


# ── rules ─────────────────────────────────────────────────────


def test_get_rules_returns_rows(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/alerts/rules")
    assert resp.status_code == 200
    assert resp.json() == [_RULE_ROW]


def test_get_rules_flags_are_int_not_bool(rest_client: TestClient) -> None:
    # WIRE-VERTRAG: enabled/notify_* als int 0/1 ueber die Wire (JSON 0/1, nicht true/false).
    body = rest_client.get("/api/alerts/rules").json()[0]
    for key in ("enabled", "notify_email", "notify_macos"):
        assert body[key] in (0, 1)
        assert isinstance(body[key], int) and not isinstance(body[key], bool)


def test_add_rule_returns_ok_with_id(rest_client: TestClient) -> None:
    resp = rest_client.post(
        "/api/alerts/rules",
        json={"name": "R", "rule_type": "host_down", "target": "any", "threshold": 60},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "id": 7}


def test_add_rule_accepts_empty_body_with_defaults(rest_client: TestClient) -> None:
    # payload.get(...)-Defaults -> leerer Body ist gueltig (AS-IS).
    resp = rest_client.post("/api/alerts/rules", json={})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "id": 7}


def test_patch_rule_returns_ok_and_passes_enabled_int(rest_client: TestClient) -> None:
    # Frontend schickt enabled als int 0/1 -> 1:1 an update_alert_rule durchgereicht.
    resp = rest_client.patch("/api/alerts/rules/1", json={"enabled": 0})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert rest_client.update_seen == {"enabled": 0}  # type: ignore[attr-defined]


def test_delete_rule_returns_ok(rest_client: TestClient) -> None:
    resp = rest_client.delete("/api/alerts/rules/1")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ── history ───────────────────────────────────────────────────


def test_get_history_returns_rows(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/alerts/history?limit=50")
    assert resp.status_code == 200
    assert resp.json() == [_HISTORY_ROW]


# ── smtp ──────────────────────────────────────────────────────


def test_get_smtp_redacts_password(rest_client: TestClient) -> None:
    # Store mit gesetztem (verschluesseltem) Passwort vorbelegen.
    rest_client.settings_store["smtp_config"] = {  # type: ignore[attr-defined]
        "host": "mail.bach.world",
        "port": 587,
        "user": "alerts@bach.world",
        "from": "cernis@bach.world",
        "to": "admin@bach.world",
        "password": "ENC(geheim)",
    }
    resp = rest_client.get("/api/alerts/smtp")
    assert resp.status_code == 200
    body = resp.json()
    # Exakter Redaktions-String: 8x U+2022 BULLET.
    assert body["password"] == "•" * 8
    assert body["password"] == "••••••••"
    # Uebrige Felder unveraendert durchgereicht.
    assert body["host"] == "mail.bach.world"
    assert body["port"] == 587
    assert body["user"] == "alerts@bach.world"
    assert body["from"] == "cernis@bach.world"
    assert body["to"] == "admin@bach.world"
    # Klartext-/Cipher-PW darf NIE rausgehen.
    assert "ENC(geheim)" not in resp.text


def test_get_smtp_empty_password_when_unset(rest_client: TestClient) -> None:
    rest_client.settings_store["smtp_config"] = {"host": "h", "to": "t"}  # type: ignore[attr-defined]
    body = rest_client.get("/api/alerts/smtp").json()
    assert body["password"] == ""


def test_put_smtp_returns_ok_and_encrypts(rest_client: TestClient) -> None:
    resp = rest_client.put(
        "/api/alerts/smtp",
        json={"host": "mail.bach.world", "to": "admin@bach.world", "password": "geheim"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # Klartext-PW darf NICHT im Store landen (verschluesselt via crypto.encrypt).
    stored = rest_client.settings_store["smtp_config"]  # type: ignore[attr-defined]
    assert stored["password"] != "geheim"
    assert stored["password"] == "ENC(geheim)"


# ── test (Send Test Alert) ────────────────────────────────────


def test_test_alert_400_without_host_or_to(rest_client: TestClient) -> None:
    # Kein smtp_config -> host/to fehlen -> 400 (AS-IS).
    resp = rest_client.post("/api/alerts/test")
    assert resp.status_code == 400
    body = resp.json()
    assert body["success"] is False
    assert isinstance(body["log"], list)


def test_test_alert_200_on_success(rest_client: TestClient) -> None:
    rest_client.settings_store["smtp_config"] = {  # type: ignore[attr-defined]
        "host": "mail.bach.world",
        "to": "admin@bach.world",
        "password": "ENC(x)",
    }
    resp = rest_client.post("/api/alerts/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert isinstance(body["log"], list)


def test_test_alert_503_on_failure(
    rest_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    rest_client.settings_store["smtp_config"] = {  # type: ignore[attr-defined]
        "host": "mail.bach.world",
        "to": "admin@bach.world",
    }
    from modules import alerting

    monkeypatch.setattr(
        alerting,
        "notify_email_with_log",
        lambda subject, body, smtp_config: {"success": False, "log": ["CONNECTION REFUSED"]},
    )
    resp = rest_client.post("/api/alerts/test")
    assert resp.status_code == 503
    body = resp.json()
    assert body["success"] is False
    assert isinstance(body["log"], list)
