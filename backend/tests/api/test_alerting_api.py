"""End-to-end-Tests der alerting-REST-API (v2, A.6) gegen app.py via TestClient.

Echte Adapter via ``dependency_overrides`` (kein echtes cernis.db, kein Bootstrap --
``AppConfig()`` hat ``bootstrap_on_startup`` aus): ``SqliteAlertRuleRepository`` auf
einer tmp_path-DB, ``SettingsSmtpConfigAdapter`` auf einem In-Memory-Settings-Fake mit
ECHTEM crypto (Key auf tmp_path isoliert, Muster test_smtp_config_roundtrip), und ein
Fake-``AlertNotifierPort`` fuer den ``/test``-Pfad (kein echtes SMTP/osascript).

Belegt die v2-Response-Shapes und die drei A.6-AUFLAGEN; der A.1-Characterization-
Contract (testet ``main``) bleibt unangetastet:

* AUFLAGE 1 -- WIRE-int 0/1: ``enabled``/``notify_*`` der rules-View sind JSON-int 0/1,
  NIE bool (true/false). Plus: ``last_triggered`` ist NICHT in der rules-Response.
* AUFLAGE 2 -- SMTP-Redaktion: GET ``/smtp`` liefert ``password == "••••••••"`` (8x
  U+2022), nie Cipher/Klartext; uebrige Felder roh; kein Setting -> ``{"password": ""}``.
* AUFLAGE 3 -- ``/test`` 400/200/503: kein host/to -> 400 (fester String); ``EmailResult``
  success -> 200, sonst 503; nicht konfiguriert (load==None) -> 400.
"""

import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.alerting import (
    provide_add_alert_rule,
    provide_delete_alert_rule,
    provide_get_alert_history,
    provide_get_alert_rules,
    provide_get_smtp_config_raw,
    provide_save_smtp_config,
    provide_send_test_alert,
    provide_update_alert_rule,
)
from app import create_app
from application.alerting import (
    AddAlertRule,
    DeleteAlertRule,
    GetAlertHistory,
    GetAlertRules,
    GetSmtpConfigRaw,
    SaveSmtpConfig,
    SendTestAlert,
    UpdateAlertRule,
)
from domain.alerting import EmailResult, SmtpConfig
from domain.settings import Setting, SettingValue
from infrastructure.alerting import SettingsSmtpConfigAdapter, SqliteAlertRuleRepository
from infrastructure.config import AppConfig
from infrastructure.crypto.secret_cipher import default_key_file

# Exakter Redaktions-/Sentinel-String: 8x U+2022 BULLET (A.1-Wortlaut).
_REDACTED = "•" * 8
_NOT_CONFIGURED = "ERROR: SMTP not configured — set host and recipient address first"


@pytest.fixture(autouse=True)
def _isolated_keyring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # crypto-Key auf tmp_path: kein Schreiben ins echte Datenverzeichnis, frischer Key
    # pro Test (Muster test_smtp_config_roundtrip). Der SMTP-PUT/-GET nutzt echtes
    # encrypt/decrypt; ``secret_cipher._data_dir()`` liest ``CERNIS_DATA_DIR`` zuerst.
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path / "data"))


class _FakeSettingsRepository:
    """In-Memory-Settings-Repo (smtp_config-Store) -- Muster test_smtp_config_roundtrip."""

    def __init__(self) -> None:
        self._store: dict[str, SettingValue] = {}

    def get_all(self) -> dict[str, SettingValue]:
        return dict(self._store)

    def get(self, key: str) -> Setting | None:
        if key not in self._store:
            return None
        return Setting(key=key, value=self._store[key])

    def set(self, setting: Setting) -> None:
        self._store[setting.key] = setting.value

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear_all(self) -> None:
        """Leert den gesamten In-Memory-Store."""
        self._store.clear()


class _FakeNotifier:
    """Fake-``AlertNotifierPort`` -- email() gibt ein konfigurierbares ``EmailResult``,
    macos() ist no-op. Kein echtes SMTP/osascript."""

    def __init__(self, result: EmailResult | None = None) -> None:
        # Default: Erfolg. Einzeltests biegen das pro Fall um.
        self._result = result or EmailResult(success=True, log=["Email sent successfully!"])
        self.email_calls: list[tuple[str, str, SmtpConfig]] = []

    async def macos(self, title: str, message: str, subtitle: str = "") -> None:
        return None

    async def email(self, subject: str, body: str, config: SmtpConfig) -> EmailResult:
        self.email_calls.append((subject, body, config))
        return self._result


def _stored_smtp_password(settings: _FakeSettingsRepository) -> str:
    """Der gespeicherte (verschluesselte) smtp_config-``password``-Wert -- typsicher."""
    setting = settings.get("smtp_config")
    assert setting is not None
    assert isinstance(setting.value, dict)
    return str(setting.value["password"])


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


def _wired_app(
    db_path: Path,
    *,
    settings_repo: _FakeSettingsRepository | None = None,
    notifier: _FakeNotifier | None = None,
) -> FastAPI:
    repo = SqliteAlertRuleRepository(db_path)
    settings = settings_repo or _FakeSettingsRepository()
    smtp_adapter = SettingsSmtpConfigAdapter(settings)
    notify = notifier or _FakeNotifier()

    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_alert_rules] = lambda: GetAlertRules(repo)
    app.dependency_overrides[provide_add_alert_rule] = lambda: AddAlertRule(repo)
    app.dependency_overrides[provide_update_alert_rule] = lambda: UpdateAlertRule(repo)
    app.dependency_overrides[provide_delete_alert_rule] = lambda: DeleteAlertRule(repo)
    app.dependency_overrides[provide_get_alert_history] = lambda: GetAlertHistory(repo)
    app.dependency_overrides[provide_get_smtp_config_raw] = lambda: GetSmtpConfigRaw(smtp_adapter)
    app.dependency_overrides[provide_save_smtp_config] = lambda: SaveSmtpConfig(smtp_adapter)
    app.dependency_overrides[provide_send_test_alert] = lambda: SendTestAlert(smtp_adapter, notify)
    return app


# ── rules (CRUD + AUFLAGE 1) ────────────────────────────────────────────────


def test_rules_get_empty(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/alerts/rules")
    assert resp.status_code == 200
    assert resp.json() == []


def test_add_rule_returns_ok_with_id(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post(
            "/api/alerts/rules",
            json={"name": "Host Down", "rule_type": "host_down"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert isinstance(body["id"], int)


def test_add_rule_empty_body_uses_defaults(db_path: Path) -> None:
    # AddRuleBody-Defaults -> leerer Body ist gueltig (Hausmuster).
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/alerts/rules", json={})
        assert resp.status_code == 200
        rules = client.get("/api/alerts/rules").json()
    assert len(rules) == 1
    row = rules[0]
    # Altcode-Defaults: rule_type=host_down, target=any, threshold=60,
    # notify_email=0, notify_macos=1, enabled=1.
    assert row["rule_type"] == "host_down"
    assert row["target"] == "any"
    assert row["threshold"] == 60
    assert row["notify_email"] == 0
    assert row["notify_macos"] == 1
    assert row["enabled"] == 1


def test_rules_flags_are_int_not_bool(db_path: Path) -> None:
    # AUFLAGE 1 (WIRE-VERTRAG): enabled/notify_* als JSON-int 0/1, NIE bool. Eine
    # pydantic-bool-Response waere JSON true/false = stiller Wire-Bruch.
    with TestClient(_wired_app(db_path)) as client:
        client.post(
            "/api/alerts/rules",
            json={
                "name": "R",
                "rule_type": "host_down",
                "notify_email": True,
                "notify_macos": False,
            },
        )
        row = client.get("/api/alerts/rules").json()[0]
    for key in ("enabled", "notify_email", "notify_macos"):
        assert row[key] in (0, 1)
        assert isinstance(row[key], int) and not isinstance(row[key], bool)
    # Die per Body gesetzten Flags kommen als int 0/1 zurueck.
    assert row["notify_email"] == 1
    assert row["notify_macos"] == 0


def test_rules_view_omits_last_triggered(db_path: Path) -> None:
    # v2-Abweichung (Entscheidung 5): last_triggered ist NICHT in der rules-Response
    # (Cooldown-intern, Frontend liest es nicht). Bleibt in Domaene + Tabelle.
    with TestClient(_wired_app(db_path)) as client:
        client.post("/api/alerts/rules", json={"name": "R", "rule_type": "host_down"})
        row = client.get("/api/alerts/rules").json()[0]
    assert "last_triggered" not in row
    # Voller v2-View-Spaltensatz (ohne last_triggered).
    assert set(row.keys()) == {
        "id",
        "name",
        "rule_type",
        "target",
        "threshold",
        "notify_email",
        "notify_macos",
        "enabled",
    }


def test_patch_rule_returns_ok_and_persists_enabled(db_path: Path) -> None:
    # Frontend-Toggle: enabled als int 0/1 -> pydantic coerced zu bool -> Repo schreibt
    # int 0/1; die Folge-GET-View gibt wieder int 0.
    with TestClient(_wired_app(db_path)) as client:
        rid = client.post("/api/alerts/rules", json={"name": "R", "rule_type": "host_down"}).json()[
            "id"
        ]
        resp = client.patch(f"/api/alerts/rules/{rid}", json={"enabled": 0})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        row = client.get("/api/alerts/rules").json()[0]
    assert row["enabled"] == 0


def test_delete_rule_returns_ok_and_removes(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rid = client.post("/api/alerts/rules", json={"name": "R", "rule_type": "host_down"}).json()[
            "id"
        ]
        resp = client.delete(f"/api/alerts/rules/{rid}")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert client.get("/api/alerts/rules").json() == []


# ── history (KEIN id, MIT datetime) ─────────────────────────────────────────


def test_history_empty_is_empty_list(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/alerts/history")
    assert resp.status_code == 200
    assert resp.json() == []


def test_history_shape_has_no_id_but_datetime(db_path: Path) -> None:
    from datetime import datetime

    from domain.alerting import AlertEvent

    # save_event ueber das echte Repo (kein REST-Schreibpfad fuer History).
    repo = SqliteAlertRuleRepository(db_path)
    settings = _FakeSettingsRepository()
    ts = 1_700_000_000.0
    repo.save_event(
        AlertEvent(
            rule_id=1,
            rule_name="Host Down",
            rule_type="host_down",
            target="192.168.1.1",
            message="host down",
            timestamp=ts,
        )
    )

    app = create_app(AppConfig())
    smtp_adapter = SettingsSmtpConfigAdapter(settings)
    app.dependency_overrides[provide_get_alert_history] = lambda: GetAlertHistory(repo)
    app.dependency_overrides[provide_get_smtp_config_raw] = lambda: GetSmtpConfigRaw(smtp_adapter)
    with TestClient(app) as client:
        body = client.get("/api/alerts/history").json()

    assert len(body) == 1
    evt = body[0]
    # v2-Abweichung: KEIN id (Altcode trug die rowid; AlertEvent traegt keine).
    assert "id" not in evt
    assert evt == {
        "rule_id": 1,
        "rule_name": "Host Down",
        "rule_type": "host_down",
        "target": "192.168.1.1",
        "message": "host down",
        "ts": ts,
        "datetime": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
    }


def test_history_limit_bounds(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        assert client.get("/api/alerts/history?limit=0").status_code == 422
        assert client.get("/api/alerts/history?limit=50").status_code == 200


# ── smtp (AUFLAGE 2 -- Redaktion, kein Cipher/Klartext) ─────────────────────


def test_get_smtp_no_setting_returns_empty_password(db_path: Path) -> None:
    # load_raw() == None (kein Setting) -> Altcode-GET-Form {"password": ""}.
    with TestClient(_wired_app(db_path)) as client:
        body = client.get("/api/alerts/smtp").json()
    assert body == {"password": ""}


def test_put_then_get_smtp_redacts_password(db_path: Path) -> None:
    # PUT speichert (echtes encrypt), GET redigiert: password == 8x U+2022, uebrige
    # Felder roh, NIE Cipher/Klartext in der Response.
    settings = _FakeSettingsRepository()
    with TestClient(_wired_app(db_path, settings_repo=settings)) as client:
        put = client.put(
            "/api/alerts/smtp",
            json={
                "host": "mail.bach.world",
                "port": 587,
                "user": "alerts@bach.world",
                "from_addr": "cernis@bach.world",
                "to": "admin@bach.world",
                "password": "geheim",
            },
        )
        assert put.status_code == 200
        assert put.json() == {"ok": True}
        resp = client.get("/api/alerts/smtp")

    body = resp.json()
    # Exakter Redaktions-String.
    assert body["password"] == _REDACTED
    assert body["password"] == "••••••••"
    # Uebrige Felder unveraendert durchgereicht.
    assert body["host"] == "mail.bach.world"
    assert body["port"] == 587
    assert body["user"] == "alerts@bach.world"
    assert body["from"] == "cernis@bach.world"
    assert body["to"] == "admin@bach.world"
    # Weder Klartext noch Cipher duerfen rausgehen.
    assert "geheim" not in resp.text
    assert _stored_smtp_password(settings) not in resp.text  # Cipher nicht in der Response


def test_put_smtp_sentinel_keeps_password(db_path: Path) -> None:
    # Sentinel-PUT (PW unveraendert, host aendern) -> der gespeicherte Cipher bleibt,
    # load() gibt weiter das urspruengliche Klartext-PW (S7-Heilung end-to-end ueber REST).
    settings = _FakeSettingsRepository()
    with TestClient(_wired_app(db_path, settings_repo=settings)) as client:
        client.put("/api/alerts/smtp", json={"host": "h", "to": "t", "password": "geheim"})
        cipher_before = _stored_smtp_password(settings)
        # Sentinel: GET liefert "••••••••", das schickt das Frontend beim Speichern zurueck.
        client.put("/api/alerts/smtp", json={"host": "neu", "to": "t", "password": _REDACTED})
        cipher_after = _stored_smtp_password(settings)
    assert cipher_after == cipher_before  # kein re-encrypt (kein S7-Doppel-encrypt)


def test_get_smtp_empty_password_when_unset_field(db_path: Path) -> None:
    # smtp_config gesetzt, aber ohne password -> GET liefert "" (nicht der Sentinel).
    settings = _FakeSettingsRepository()
    settings.set(Setting(key="smtp_config", value={"host": "h", "to": "t"}))
    with TestClient(_wired_app(db_path, settings_repo=settings)) as client:
        body = client.get("/api/alerts/smtp").json()
    assert body["password"] == ""


# ── test (AUFLAGE 3 -- 400/200/503-Matrix) ──────────────────────────────────


def test_test_alert_400_without_host_or_to(db_path: Path) -> None:
    # Kein smtp_config -> host/to fehlen -> 400 mit dem festen Altcode-String.
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/alerts/test")
    assert resp.status_code == 400
    body = resp.json()
    assert body["success"] is False
    assert body["log"] == [_NOT_CONFIGURED]


def test_test_alert_400_when_to_missing(db_path: Path) -> None:
    # host gesetzt, to fehlt -> 400 (host ODER to leer).
    settings = _FakeSettingsRepository()
    settings.set(Setting(key="smtp_config", value={"host": "mail.bach.world"}))
    with TestClient(_wired_app(db_path, settings_repo=settings)) as client:
        resp = client.post("/api/alerts/test")
    assert resp.status_code == 400
    assert resp.json()["success"] is False


def test_test_alert_200_on_success(db_path: Path) -> None:
    settings = _FakeSettingsRepository()
    settings.set(Setting(key="smtp_config", value={"host": "mail.bach.world", "to": "admin@x"}))
    notifier = _FakeNotifier(EmailResult(success=True, log=["Email sent successfully!"]))
    with TestClient(_wired_app(db_path, settings_repo=settings, notifier=notifier)) as client:
        resp = client.post("/api/alerts/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert isinstance(body["log"], list)
    # Der Notifier wurde tatsaechlich mit der geladenen SmtpConfig gerufen.
    assert len(notifier.email_calls) == 1


def test_test_alert_503_on_failure(db_path: Path) -> None:
    settings = _FakeSettingsRepository()
    settings.set(Setting(key="smtp_config", value={"host": "mail.bach.world", "to": "admin@x"}))
    notifier = _FakeNotifier(EmailResult(success=False, log=["CONNECTION REFUSED"]))
    with TestClient(_wired_app(db_path, settings_repo=settings, notifier=notifier)) as client:
        resp = client.post("/api/alerts/test")
    assert resp.status_code == 503
    body = resp.json()
    assert body["success"] is False
    assert body["log"] == ["CONNECTION REFUSED"]


# ── Befund 65: fehlende Schluesseldatei endet NICHT mehr als nackter 500 ─────


def test_test_alert_missing_key_file_is_503_not_500(db_path: Path) -> None:
    """Der Verlustfall am RAND: der ``KeyMissingError``-Handler aus app.py greift.

    Gemessen in S85-A8/C3: bis hierher erreichte dieser Fall die Oberflaeche als nackter
    Internal Server Error. Jetzt: 503 mit einer Meldung, die die fehlende Datei UND den
    erwarteten Pfad nennt -- seit S85-A10 im entschiedenen Wortlaut (Fassung B) mit dem
    Code (E-507). Der Test baut die ECHTE App (``create_app``), damit belegt ist, dass der
    Handler dort tatsaechlich registriert ist -- ein nachgebauter Handler wuerde das
    gerade nicht zeigen.

    ``raise_server_exceptions=False``: sonst reicht der TestClient eine ungefangene
    Ausnahme als Python-Exception durch, statt die HTTP-Antwort zu liefern -- und genau
    die HTTP-Antwort ist hier der Prueffall.
    """
    settings = _FakeSettingsRepository()
    app = _wired_app(db_path, settings_repo=settings)

    # 1. Passwort ueber den echten Schreibweg ablegen -> legt den Key an und verschluesselt.
    with TestClient(app) as client:
        put = client.put(
            "/api/alerts/smtp",
            json={"host": "mail.bach.world", "to": "admin@x", "password": "geheim"},
        )
        assert put.status_code == 200
    key_file = default_key_file()
    assert key_file.exists()
    assert _stored_smtp_password(settings).startswith("enc:")

    # 2. Die Schluesseldatei geht verloren (geloescht/nicht mitgesichert).
    key_file.unlink()

    # 3. Der Lesepfad trifft darauf: 503 statt 500, mit benannter Ursache.
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post("/api/alerts/test")

    assert resp.status_code == 503, "Der Verlustfall darf nicht mehr als 500 enden"
    detail = resp.json()["detail"]
    assert str(key_file) in detail, "Die Meldung muss den erwarteten Pfad nennen"
    # ANGEPASST (S85-A10): Bis hierher pruefte der Test das FEHLEN eines E-Codes -- richtig
    # genau so lange, wie der Text ein Platzhalter ohne Code war. Karl hat entschieden
    # (Fassung B, E-507), damit kehrt sich die Erwartung um: der Code MUSS jetzt da sein,
    # in der Hausform "(E-xxx)" am Ende. Der alte Negativ-Assert waere ab sofort gruen
    # genau dann, wenn die Entscheidung NICHT umgesetzt ist -- er haette den Fortschritt
    # blockiert statt ihn zu sichern.
    assert re.search(r"\(E-507\)", detail), f"Der Code (E-507) fehlt in der Meldung: {detail}"
    # Und der Wortlaut ist der entschiedene, nicht mehr der Platzhalter.
    assert "VORLAEUFIG" not in detail, "Der Platzhaltertext steht noch in der Meldung"
    assert "neu eingegeben werden" in detail, (
        "Die Meldung muss sagen, was zu tun ist, wenn keine Sicherung vorliegt"
    )

    # Und der Punkt aus Aufgabe 7 gilt auch am Rand: nichts wurde neu erzeugt.
    assert not key_file.exists()
