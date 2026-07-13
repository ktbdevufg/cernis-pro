"""Tests fuer ``infrastructure.crypto.secret_cipher`` -- Fernet-Verschluesselung ohne
stille Fallbacks (ADR 0001; v2-Neubau von ``modules/crypto.py``).

ISOLATION: ``secret_cipher._data_dir()`` liest ``CERNIS_DATA_DIR`` zuerst -- die autouse-
Fixture ``_isolated_key`` biegt sie auf ``tmp_path``, sodass der Fernet-Key pro Test in
einem frischen, isolierten Ort landet (kein Schreiben ins echte Datenverzeichnis, kein
Home-Zugriff). Damit laeuft die Suite auf dem Linux-CI deterministisch.

Der wichtigste Test des Auftrags: ist das Schluesselverzeichnis nicht beschreibbar,
wirft ``encrypt`` ``KeyAccessError`` und gibt NIEMALS Klartext zurueck
(``test_encrypt_raises_when_key_dir_unwritable``).
"""

import os
import sys
from pathlib import Path

import pytest

from infrastructure.crypto.secret_cipher import (
    CipherError,
    DecryptionError,
    KeyAccessError,
    decrypt,
    default_key_file,
    encrypt,
    is_encrypted,
)


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Key-Pfad auf tmp_path isolieren: secret_cipher._data_dir() liest CERNIS_DATA_DIR
    # zuerst. Frischer Key pro Test, kein echtes Datenverzeichnis beruehrt.
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path / "data"))


# ── Hin- und Rueckweg ────────────────────────────────────────────────────────


def test_roundtrip_returns_plaintext() -> None:
    cipher = encrypt("geheim")
    assert cipher != "geheim"
    assert is_encrypted(cipher)
    assert decrypt(cipher) == "geheim"


def test_roundtrip_unicode() -> None:
    secret = "Paßwörtchen-✓-🔐"
    assert decrypt(encrypt(secret)) == secret


def test_encrypt_prefixes_cipher() -> None:
    assert encrypt("x").startswith("enc:")


# ── Leerzustand: gueltig und ehrlich, kein Fehler ───────────────────────────


def test_encrypt_empty_returns_empty_string() -> None:
    assert encrypt("") == ""


def test_decrypt_empty_returns_empty_string() -> None:
    assert decrypt("") == ""


# ── Praefix-Vertrag: kein Klartext-Durchreichpfad ───────────────────────────


def test_decrypt_nonempty_without_prefix_raises() -> None:
    # Ein nicht-leerer Wert OHNE enc:-Praefix ist ungueltig -> DecryptionError.
    # KEIN Klartext-Durchreichen (der Altcode gab hier den Wert unveraendert zurueck).
    with pytest.raises(DecryptionError):
        decrypt("plaintext-ohne-praefix")


def test_decrypt_legacy_b64_prefix_raises() -> None:
    # Der aufgehobene Altcode-b64:-Schein-Obfuskations-Pfad existiert nicht mehr:
    # b64: traegt nicht das enc:-Praefix -> ungueltig.
    with pytest.raises(DecryptionError):
        decrypt("b64:aGVsbG8=")


# ── Kaputtes Token: wirft, gibt NIE "" zurueck ──────────────────────────────


def test_decrypt_corrupt_token_raises_decryption_error() -> None:
    # Ein Wert MIT Praefix, aber kaputtem/fremdem Token -> DecryptionError,
    # NICHT "" (der Altcode verbarg den Fehler durch Rueckgabe von "").
    with pytest.raises(DecryptionError):
        decrypt("enc:vollkommen-kaputtes-token")


def test_decrypt_wrong_key_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Mit einem Key verschluesseln, dann den Key-Ort wechseln (frischer Key) ->
    # das alte Token laesst sich nicht mehr entschluesseln -> DecryptionError.
    cipher = encrypt("geheim")
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path / "anderer_ort"))
    with pytest.raises(DecryptionError):
        decrypt(cipher)


def test_decryption_error_is_cipher_error() -> None:
    # Subtyp-Vertrag: der Aufrufer kann breit CipherError fangen.
    assert issubclass(DecryptionError, CipherError)
    assert issubclass(KeyAccessError, CipherError)


# ── is_encrypted ────────────────────────────────────────────────────────────


def test_is_encrypted_true_for_cipher() -> None:
    assert is_encrypted(encrypt("x")) is True


def test_is_encrypted_false_for_plaintext() -> None:
    assert is_encrypted("plaintext") is False
    assert is_encrypted("") is False
    assert is_encrypted("b64:x") is False


# ── Schluesselverwaltung: Wiederverwendung, kein Ueberschreiben ─────────────


def test_existing_key_is_reused_not_overwritten() -> None:
    # Erst-encrypt legt den Key an; ein zweiter Aufruf DARF ihn nicht ueberschreiben,
    # sonst waere das erste Token nicht mehr entschluesselbar.
    key_file = default_key_file()
    cipher_first = encrypt("geheim")
    assert key_file.exists()
    key_bytes_after_first = key_file.read_bytes()

    cipher_second = encrypt("noch-eins")
    # Key-Datei unveraendert (wiederverwendet, nicht neu erzeugt).
    assert key_file.read_bytes() == key_bytes_after_first
    # Beide Token bleiben mit demselben (wiederverwendeten) Key entschluesselbar.
    assert decrypt(cipher_first) == "geheim"
    assert decrypt(cipher_second) == "noch-eins"


def test_key_file_lives_under_data_dir(tmp_path: Path) -> None:
    # Kanonischer Pfad: <data_dir>/secret_cipher.key -- <data_dir> ist der per
    # CERNIS_DATA_DIR gesetzte Ort (dieselbe Wahl wie fuer cernis.db).
    assert default_key_file() == tmp_path / "data" / "secret_cipher.key"


def test_empty_key_file_raises_key_access_error() -> None:
    # Eine leere/kaputte Schluesseldatei ist ein Fehler, kein Neuanlege-Anlass:
    # ein stilles Ueberschreiben wuerde bestehende Cipher unlesbar machen.
    key_file = default_key_file()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(b"")
    with pytest.raises(KeyAccessError):
        encrypt("geheim")


# ── DER WICHTIGSTE TEST: Verzeichnis nicht beschreibbar -> KeyAccessError ────
#    encrypt gibt NIEMALS Klartext zurueck.


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-Rechte auf Windows wirkungslos")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root umgeht Dateisystem-Rechte -- der Schreibfehler triggert nicht",
)
def test_encrypt_raises_when_key_dir_unwritable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Kern des Auftrags: kann der Key nicht geschrieben werden, MUSS encrypt werfen
    # -- es darf UNTER KEINEN UMSTAENDEN den Klartext zurueckgeben (der Altcode-Bug:
    # ``except Exception: return plaintext``).
    parent = tmp_path / "readonly"
    parent.mkdir()
    data_dir = parent / "data"
    # Elternverzeichnis nur-lesbar machen -> das Anlegen von data_dir/Key darin schlaegt fehl.
    os.chmod(parent, 0o500)
    monkeypatch.setenv("CERNIS_DATA_DIR", str(data_dir))
    try:
        with pytest.raises(KeyAccessError):
            result = encrypt("geheim")
            # Falls (wider Erwarten) doch etwas zurueckkommt: es darf NIE Klartext sein.
            assert result != "geheim"
    finally:
        # Aufraeumen ermoeglichen (sonst kann tmp_path nicht abgeraeumt werden).
        os.chmod(parent, 0o700)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-Rechte auf Windows wirkungslos")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root umgeht Dateisystem-Rechte",
)
def test_key_file_has_0600_permissions() -> None:
    # POSIX: die Schluesseldatei wird mit 0600 angelegt (und ihr Verzeichnis 0700).
    encrypt("geheim")
    key_file = default_key_file()
    assert (key_file.stat().st_mode & 0o777) == 0o600
    assert (key_file.parent.stat().st_mode & 0o777) == 0o700


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-Rechte auf Windows wirkungslos")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root umgeht Dateisystem-Rechte",
)
def test_permissions_reenforced_on_each_access() -> None:
    # v2 erzwingt die Rechte bei JEDEM Zugriff (nicht nur beim Erzeugen wie der Altcode):
    # ein von aussen zu lax gesetzter Key wird beim naechsten Aufruf korrigiert.
    encrypt("geheim")
    key_file = default_key_file()
    os.chmod(key_file, 0o644)  # von aussen aufgeweicht
    decrypt(encrypt("noch-eins"))  # loest _get_or_create_key erneut aus
    assert (key_file.stat().st_mode & 0o777) == 0o600
