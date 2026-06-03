"""Round-Trip-Vertrag des SMTP-Sentinel-Pfads mit ECHTEM crypto (A.4b, Heilung S7).

KEIN encrypt/decrypt-Mock hier (anders als test_smtp_config.py): save -> load laeuft
ueber das echte ``modules.crypto``. Das beweist die Heilung des Altcode-Doppel-encrypt-
Bugs (S7) end-to-end: nach einem Sentinel-Save gibt ``load()`` das URSPRUENGLICHE
Klartext-PW zurueck -- NICHT den doppelt verschluesselten Murks.

ISOLATION (CI-deterministisch, KEIN Home-Zugriff): ``crypto._get_or_create_key`` legt
den Fernet-Key sonst unter ``~/.cernis-pro/keyring`` an (echtes Home). Die autouse-
Fixture ``_isolated_keyring`` biegt ``crypto.KEY_DIR``/``KEY_FILE`` auf ``tmp_path`` --
pro Test ein frischer, isolierter Fernet-Key. Deterministisch (HAS_CRYPTO=True ->
``enc:``-Pfad, encrypt(x) -> decrypt(...) == x), schreibt NICHTS ins echte
~/.cernis-pro, verschmutzt die Nutzer-Umgebung nicht.
"""

from pathlib import Path
from typing import Any

import pytest

from domain.settings import Setting, SettingValue
from infrastructure.alerting.smtp_config import SettingsSmtpConfigAdapter


@pytest.fixture(autouse=True)
def _isolated_keyring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # crypto-Key-Pfad auf tmp_path biegen: kein Schreiben ins echte Home, frischer
    # Key pro Test. KEY_DIR/KEY_FILE sind Modul-Konstanten, beim Aufruf gelesen.
    from modules import crypto

    monkeypatch.setattr(crypto, "KEY_DIR", tmp_path / ".cernis-pro")
    monkeypatch.setattr(crypto, "KEY_FILE", tmp_path / ".cernis-pro" / "keyring")


class _FakeSettingsRepository:
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


def _stored_password(repo: _FakeSettingsRepository) -> Any:
    setting = repo.get("smtp_config")
    assert setting is not None
    assert isinstance(setting.value, dict)
    return setting.value["password"]


def test_roundtrip_new_password_save_then_load() -> None:
    # save(echtes neues PW) -> load() (entschluesselt) gibt das neue PW.
    repo = _FakeSettingsRepository()
    adapter = SettingsSmtpConfigAdapter(repo)
    adapter.save({"host": "h", "to": "t", "user": "u", "password": "geheim"})
    cfg = adapter.load()
    assert cfg is not None
    assert cfg.password == "geheim"


def test_roundtrip_sentinel_keeps_original_plaintext() -> None:
    # KERN DER HEILUNG (S7): erst echtes PW speichern, dann mit Sentinel "PW unveraendert"
    # speichern (host aendern). load() MUSS weiterhin das URSPRUENGLICHE Klartext-PW
    # geben -- NICHT den doppelt verschluesselten Cipher (= Altcode-Bug).
    repo = _FakeSettingsRepository()
    adapter = SettingsSmtpConfigAdapter(repo)

    adapter.save({"host": "h", "to": "t", "user": "u", "password": "geheim"})
    cipher_after_first = _stored_password(repo)

    # Sentinel-Save: nur host aendern, PW unveraendert lassen.
    adapter.save({"host": "neu", "to": "t", "user": "u", "password": "•" * 8})
    cipher_after_sentinel = _stored_password(repo)

    # Der gespeicherte Cipher ist UNVERAENDERT (kein re-encrypt).
    assert cipher_after_sentinel == cipher_after_first
    # Und load() gibt das urspruengliche Klartext-PW -- die Heilung wirkt.
    cfg = adapter.load()
    assert cfg is not None
    assert cfg.password == "geheim"
    assert cfg.host == "neu"


def test_roundtrip_empty_password_load_empty() -> None:
    repo = _FakeSettingsRepository()
    adapter = SettingsSmtpConfigAdapter(repo)
    adapter.save({"host": "h", "to": "t", "password": ""})
    cfg = adapter.load()
    assert cfg is not None
    assert cfg.password == ""


def test_roundtrip_change_password_load_new() -> None:
    # Erst geheim, dann echtes neues PW (kein Sentinel) -> load gibt das neue.
    repo = _FakeSettingsRepository()
    adapter = SettingsSmtpConfigAdapter(repo)
    adapter.save({"host": "h", "to": "t", "password": "geheim"})
    adapter.save({"host": "h", "to": "t", "password": "anders"})
    cfg = adapter.load()
    assert cfg is not None
    assert cfg.password == "anders"
