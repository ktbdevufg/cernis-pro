"""Tests fuer ``email_sender.notify_email_with_log`` (A.8) -- PFLICHT-TLS-Neubau.

Alles ueber Mocks, KEINE echte Netzverbindung -- die CI ist Linux. Der WICHTIGSTE
Test des Auftrags: schlaegt STARTTLS fehl, findet KEIN Login statt und es wird NICHT
gesendet (``login``/``sendmail`` werden NIE aufgerufen). Weiter: Port 465 nutzt
``SMTP_SSL`` ohne STARTTLS; jeder andere Port fuehrt STARTTLS aus, auch Port 25 (die
alte ``port != 25``-Ausnahme ist weg); die Verbindung wird auch im Fehlerfall
geschlossen (``quit`` im ``finally``); leerer Host / leerer Empfaenger liefert
``success=False`` mit klarer Log-Meldung.
"""

import smtplib
from typing import Any, ClassVar

import pytest

from infrastructure.alerting import email_sender

_BASE_CONFIG: dict[str, Any] = {
    "host": "mail.bach.world",
    "port": 587,
    "user": "alerts@bach.world",
    "password": "supersecret",
    "from": "cernis@bach.world",
    "to": "admin@bach.world",
}


class FakeSMTP:
    """Aufzeichnender SMTP-Doppel: protokolliert jeden Aufruf, nichts geht ins Netz.

    Das Verhalten der einzelnen Schritte ist ueber Klassen-Flags steuerbar, damit die
    Tests STARTTLS-Erfolg/-Fehlschlag und Login-Fehler gezielt ausloesen koennen.
    """

    # Steuerung pro Test (Klassenattribute, im Test gesetzt):
    starttls_raises: ClassVar[BaseException | None] = None
    login_raises: ClassVar[BaseException | None] = None
    sendmail_result: ClassVar[dict[str, Any]] = {}

    # Aufzeichnung (pro Instanz):
    def __init__(self, host: str = "", port: int = 0, timeout: float = 0) -> None:
        self.init_host = host
        self.init_port = port
        self.calls: list[str] = []
        self.ehlo_resp: bytes | None = b"250-mail.bach.world"

    def ehlo(self) -> tuple[int, bytes]:
        self.calls.append("ehlo")
        return 250, b"250-mail.bach.world"

    def starttls(self) -> tuple[int, bytes]:
        self.calls.append("starttls")
        exc = type(self).starttls_raises
        if exc is not None:
            raise exc
        return 220, b"2.0.0 Ready to start TLS"

    def login(self, user: str, password: str) -> tuple[int, bytes]:
        self.calls.append("login")
        exc = type(self).login_raises
        if exc is not None:
            raise exc
        return 235, b"2.7.0 Authentication successful"

    def sendmail(self, from_addr: str, to_addr: str, msg: str) -> dict[str, Any]:
        self.calls.append("sendmail")
        return type(self).sendmail_result

    def quit(self) -> tuple[int, bytes]:
        self.calls.append("quit")
        return 221, b"2.0.0 Bye"


class FakeSMTPSSL(FakeSMTP):
    """Wie FakeSMTP, aber als Klasse fuer ``SMTP_SSL`` (Port 465, implizites TLS)."""


@pytest.fixture(autouse=True)
def _reset_fake_state() -> Any:
    """Vor JEDEM Test die Klassen-Flags zuruecksetzen (sonst lecken sie zwischen Tests)."""
    for cls in (FakeSMTP, FakeSMTPSSL):
        cls.starttls_raises = None
        cls.login_raises = None
        cls.sendmail_result = {}
    yield


def _instances() -> dict[str, list[FakeSMTP]]:
    return {"smtp": [], "ssl": []}


def _patch(monkeypatch: pytest.MonkeyPatch, registry: dict[str, list[FakeSMTP]]) -> None:
    def make_smtp(host: str = "", port: int = 0, timeout: float = 0) -> FakeSMTP:
        inst = FakeSMTP(host, port, timeout)
        registry["smtp"].append(inst)
        return inst

    def make_ssl(host: str = "", port: int = 0, timeout: float = 0) -> FakeSMTPSSL:
        inst = FakeSMTPSSL(host, port, timeout)
        registry["ssl"].append(inst)
        return inst

    # email_sender liest smtplib.SMTP/SMTP_SSL zur Laufzeit ueber `import smtplib` --
    # das Patchen des stdlib-Moduls selbst wirkt fuer den Sender (kein reexport-Zugriff).
    monkeypatch.setattr(smtplib, "SMTP", make_smtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", make_ssl)


# ── DER WICHTIGSTE TEST: STARTTLS-Fehlschlag -> KEIN Login, KEIN Versand ──────


def test_starttls_failure_means_no_login_no_send(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    # STARTTLS schlaegt fehl (irgendein SMTP-Fehler).
    FakeSMTP.starttls_raises = smtplib.SMTPException("handshake failed")

    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))

    assert result["success"] is False
    inst = reg["smtp"][0]
    # login und sendmail wurden NIE aufgerufen.
    assert "login" not in inst.calls
    assert "sendmail" not in inst.calls
    # ... aber die Verbindung wurde geschlossen (finally).
    assert "quit" in inst.calls
    # ehrlich gemeldet:
    assert any("ABORT: STARTTLS failed" in line for line in result["log"])


def test_starttls_not_supported_means_no_login_no_send(monkeypatch: pytest.MonkeyPatch) -> None:
    # Auch wenn der Server STARTTLS NICHT anbietet: kein Klartext-Rueckfall.
    reg = _instances()
    _patch(monkeypatch, reg)
    FakeSMTP.starttls_raises = smtplib.SMTPNotSupportedError("STARTTLS not supported")

    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))

    assert result["success"] is False
    inst = reg["smtp"][0]
    assert "login" not in inst.calls
    assert "sendmail" not in inst.calls
    assert "quit" in inst.calls
    assert any("does not support STARTTLS" in line for line in result["log"])


# ── Port 465: SMTP_SSL, KEIN STARTTLS ────────────────────────────────────────


def test_port_465_uses_ssl_and_no_starttls(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    cfg = dict(_BASE_CONFIG, port=465)

    result = email_sender.notify_email_with_log("Subj", "Body", cfg)

    assert result["success"] is True
    # SMTP_SSL wurde genutzt, plain SMTP nicht.
    assert len(reg["ssl"]) == 1
    assert len(reg["smtp"]) == 0
    inst = reg["ssl"][0]
    # KEIN STARTTLS auf der bereits verschluesselten Verbindung.
    assert "starttls" not in inst.calls
    # Login + Versand fanden statt, Verbindung geschlossen.
    assert "login" in inst.calls
    assert "sendmail" in inst.calls
    assert "quit" in inst.calls


# ── Jeder andere Port: STARTTLS Pflicht ──────────────────────────────────────


def test_port_587_runs_starttls_then_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)

    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))

    assert result["success"] is True
    inst = reg["smtp"][0]
    # STARTTLS vor Login vor Versand.
    assert inst.calls.index("starttls") < inst.calls.index("login")
    assert inst.calls.index("login") < inst.calls.index("sendmail")


def test_port_25_runs_starttls_now(monkeypatch: pytest.MonkeyPatch) -> None:
    # Die alte Ausnahme (port != 25 uebersprang STARTTLS) ist WEG: auch 25 -> STARTTLS.
    reg = _instances()
    _patch(monkeypatch, reg)
    cfg = dict(_BASE_CONFIG, port=25)

    result = email_sender.notify_email_with_log("Subj", "Body", cfg)

    assert result["success"] is True
    inst = reg["smtp"][0]
    assert "starttls" in inst.calls
    assert "sendmail" in inst.calls


def test_port_25_starttls_failure_still_blocks_send(monkeypatch: pytest.MonkeyPatch) -> None:
    # Auf Port 25 garantierte der Altcode Klartext-Login. Jetzt: STARTTLS-Fehler -> Stopp.
    reg = _instances()
    _patch(monkeypatch, reg)
    FakeSMTP.starttls_raises = smtplib.SMTPNotSupportedError("no tls on 25")
    cfg = dict(_BASE_CONFIG, port=25)

    result = email_sender.notify_email_with_log("Subj", "Body", cfg)

    assert result["success"] is False
    inst = reg["smtp"][0]
    assert "login" not in inst.calls
    assert "sendmail" not in inst.calls


# ── finally: Verbindung schliesst auch im Fehlerfall ─────────────────────────


def test_connection_closed_on_login_error(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    FakeSMTP.login_raises = smtplib.SMTPAuthenticationError(535, b"5.7.8 Bad credentials")

    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))

    assert result["success"] is False
    inst = reg["smtp"][0]
    # STARTTLS lief (verschluesselt), Login schlug fehl, NICHT gesendet, quit lief.
    assert "starttls" in inst.calls
    assert "sendmail" not in inst.calls
    assert "quit" in inst.calls


def test_connection_closed_when_send_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wirft sendmail eine Ausnahme, muss quit trotzdem laufen (finally, kein Socket-Leak).
    reg = _instances()
    _patch(monkeypatch, reg)

    def boom(self: FakeSMTP, *a: Any, **k: Any) -> dict[str, Any]:
        self.calls.append("sendmail")
        raise smtplib.SMTPException("send exploded")

    monkeypatch.setattr(FakeSMTP, "sendmail", boom)

    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))

    assert result["success"] is False
    inst = reg["smtp"][0]
    assert "quit" in inst.calls
    assert any("SMTP ERROR" in line for line in result["log"])


# ── Anonymer Relay: kein Login, aber Versand nur nach TLS ────────────────────


def test_no_credentials_skips_login_but_sends_after_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    cfg = dict(_BASE_CONFIG, user="", password="")

    result = email_sender.notify_email_with_log("Subj", "Body", cfg)

    assert result["success"] is True
    inst = reg["smtp"][0]
    assert "starttls" in inst.calls  # TLS bleibt Pflicht, auch ohne Login.
    assert "login" not in inst.calls
    assert "sendmail" in inst.calls


# ── Leerer Host / Empfaenger: frueher Abbruch, keine Verbindung ──────────────


def test_empty_host_returns_failure_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    cfg = dict(_BASE_CONFIG, host="")

    result = email_sender.notify_email_with_log("Subj", "Body", cfg)

    assert result["success"] is False
    # gar keine Verbindung aufgebaut.
    assert reg["smtp"] == [] and reg["ssl"] == []
    assert any("host is empty" in line for line in result["log"])


def test_empty_recipient_returns_failure_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    cfg = dict(_BASE_CONFIG, to="")

    result = email_sender.notify_email_with_log("Subj", "Body", cfg)

    assert result["success"] is False
    assert reg["smtp"] == [] and reg["ssl"] == []
    assert any("Recipient address is empty" in line for line in result["log"])


# ── Rueckgabevertrag + v2.0.0 im HTML ────────────────────────────────────────


def test_return_contract_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))
    assert set(result.keys()) == {"success", "log"}
    assert isinstance(result["success"], bool)
    assert isinstance(result["log"], list)


def test_html_body_carries_v2_version(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    sent: dict[str, str] = {}

    def capture(self: FakeSMTP, from_addr: str, to_addr: str, msg: str) -> dict[str, Any]:
        self.calls.append("sendmail")
        sent["msg"] = msg
        return {}

    monkeypatch.setattr(FakeSMTP, "sendmail", capture)
    email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))
    assert "CERNIS PRO v2.0.0" in sent["msg"]
    assert "v1.0.0" not in sent["msg"]


def test_partial_failure_is_not_success(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _instances()
    _patch(monkeypatch, reg)
    FakeSMTP.sendmail_result = {"admin@bach.world": (550, b"User unknown")}

    result = email_sender.notify_email_with_log("Subj", "Body", dict(_BASE_CONFIG))

    assert result["success"] is False
    assert any("Partial failure" in line for line in result["log"])
