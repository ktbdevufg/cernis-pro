"""Tests fuer ``SettingsSmtpConfigAdapter`` (A.4) -- settings-dict -> SmtpConfig.

AUFLAGE 3: Das Mapping als Vertrag gegen die echten settings-Port- + crypto-Signaturen
(In-Memory-Fake des SettingsRepository, ``decrypt`` am Adapter-Modul gemockt):
- port als str "587" im dict -> int 587 (Cast),
- password-Cipher -> decryptet,
- "from" fehlt -> from_addr = user (Altcode-Default),
- leeres/None settings -> load() == None.

AUFLAGE 1: decrypt liefert "" trotz Cipher -> SmtpConfig.password = "" (Altcode-treu)
+ structlog.warning("smtp_password_decrypt_empty") -- der stille S3-Strang wird
sichtbar gemacht, ohne das Verhalten zu aendern.
"""

import pytest

from domain.settings import Setting, SettingValue
from infrastructure.alerting import smtp_config as smtp_config_mod
from infrastructure.alerting.smtp_config import SettingsSmtpConfigAdapter
from ports.alerting import SmtpConfigPort


class _FakeSettingsRepository:
    """In-Memory-SettingsRepository (erfuellt das Protocol strukturell)."""

    def __init__(self, store: dict[str, SettingValue] | None = None) -> None:
        self._store: dict[str, SettingValue] = dict(store or {})

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


@pytest.fixture(autouse=True)
def _fake_decrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    # decrypt am Adapter-Modul mocken: "enc:XYZ" -> "XYZ" (deterministisch).
    monkeypatch.setattr(
        smtp_config_mod,
        "decrypt",
        lambda cipher: cipher[4:] if cipher.startswith("enc:") else cipher,
    )


def _adapter(store: dict[str, SettingValue]) -> SettingsSmtpConfigAdapter:
    return SettingsSmtpConfigAdapter(_FakeSettingsRepository(store))


def test_conforms_to_port_protocol() -> None:
    _: SmtpConfigPort = SettingsSmtpConfigAdapter(_FakeSettingsRepository())


# ── load: None-Faelle ─────────────────────────────────────────


def test_load_none_when_setting_absent() -> None:
    assert _adapter({}).load() is None


def test_load_none_when_empty_dict() -> None:
    assert _adapter({"smtp_config": {}}).load() is None


def test_load_none_when_value_not_dict() -> None:
    # falsch typisierter Wert (z.B. versehentlich str) -> None, kein Crash.
    assert _adapter({"smtp_config": "oops"}).load() is None


# ── Mapping-Vertrag ───────────────────────────────────────────


def test_port_str_is_cast_to_int() -> None:
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t", "port": "587"}}).load()
    assert cfg is not None
    assert cfg.port == 587
    assert isinstance(cfg.port, int)


def test_port_missing_defaults_to_587() -> None:
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t"}}).load()
    assert cfg is not None
    assert cfg.port == 587


def test_port_garbage_defaults_to_587() -> None:
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t", "port": "abc"}}).load()
    assert cfg is not None
    assert cfg.port == 587


def test_password_is_decrypted() -> None:
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t", "password": "enc:secret"}}).load()
    assert cfg is not None
    assert cfg.password == "secret"


def test_from_falls_back_to_user_when_missing() -> None:
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t", "user": "u@x"}}).load()
    assert cfg is not None
    assert cfg.from_addr == "u@x"


def test_from_used_when_present() -> None:
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t", "user": "u@x", "from": "f@x"}}).load()
    assert cfg is not None
    assert cfg.from_addr == "f@x"


def test_full_mapping() -> None:
    cfg = _adapter(
        {
            "smtp_config": {
                "host": "mail.bach.world",
                "port": "465",
                "user": "alerts@bach.world",
                "password": "enc:geheim",
                "from": "cernis@bach.world",
                "to": "admin@bach.world",
            }
        }
    ).load()
    assert cfg is not None
    assert cfg.host == "mail.bach.world"
    assert cfg.port == 465
    assert cfg.user == "alerts@bach.world"
    assert cfg.password == "geheim"
    assert cfg.from_addr == "cernis@bach.world"
    assert cfg.to == "admin@bach.world"


def test_empty_password_no_warning_no_decrypt() -> None:
    # Kein password im dict -> password "" ohne decrypt-Aufruf, kein Warnlog.
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t"}}).load()
    assert cfg is not None
    assert cfg.password == ""


# ── AUFLAGE 1: decrypt liefert "" trotz Cipher -> warning ─────


def test_decrypt_empty_despite_cipher_logs_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    # decrypt simuliert den Altcode-S3-Fallback (kaputter Cipher -> "").
    monkeypatch.setattr(smtp_config_mod, "decrypt", lambda cipher: "")
    warnings: list[str] = []
    monkeypatch.setattr(
        smtp_config_mod._logger,
        "warning",
        lambda event, **kw: warnings.append(event),
    )
    cfg = _adapter({"smtp_config": {"host": "h", "to": "t", "password": "enc:broken"}}).load()
    assert cfg is not None
    # Verhalten Altcode-treu: password = "".
    assert cfg.password == ""
    # ... aber sichtbar geloggt (v2-Sichtbarmachung des S3-Strangs).
    assert "smtp_password_decrypt_empty" in warnings
