"""Tests fuer ``infrastructure.crypto.secret_cipher`` -- Fernet-Verschluesselung ohne
stille Fallbacks (ADR 0001; v2-Neubau von ``modules/crypto.py``).

ISOLATION: ``secret_cipher._data_dir()`` liest ``CERNIS_DATA_DIR`` zuerst -- die autouse-
Fixture ``_isolated_key`` biegt sie auf ``tmp_path``, sodass der Fernet-Key pro Test in
einem frischen, isolierten Ort landet (kein Schreiben ins echte Datenverzeichnis, kein
Home-Zugriff). Damit laeuft die Suite auf dem Linux-CI deterministisch.

Der wichtigste Test des Auftrags: ist das Schluesselverzeichnis nicht beschreibbar,
wirft ``encrypt`` ``KeyAccessError`` und gibt NIEMALS Klartext zurueck
(``test_encrypt_raises_when_key_dir_unwritable``).

BEFUND 65 -- der Leseversuch darf den Schluessel nicht erzeugen: fehlt die
Schluesseldatei bei vorhandenem Chiffrat, wirft ``decrypt`` ``KeyMissingError`` und legt
KEINEN neuen Schluessel an (``test_decrypt_missing_key_file_raises_and_creates_nothing``
-- der zweite ``assert`` dort ist der Punkt). Die Gegenprobe, dass ``encrypt`` beim
Erstgebrauch weiterhin erzeugen darf, steht in
``test_encrypt_still_creates_key_on_first_use``.
"""

import os
import sys
from pathlib import Path

import pytest

from infrastructure.crypto.secret_cipher import (
    CipherError,
    DecryptionError,
    KeyAccessError,
    KeyMissingError,
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
    #
    # ANPASSUNG (Befund 65, gleiche Begruendung wie test_decrypt_wrong_key_raises): der
    # Test rief frueher ``decrypt`` OHNE vorher je verschluesselt zu haben -- es gab also
    # gar keine Schluesseldatei, und er lief durch deren stille Neuerzeugung. Er belegte
    # damit "kaputtes Token" nur unter einer Voraussetzung, die es nie geben sollte.
    # Der ``encrypt``-Aufruf stellt jetzt den Zustand her, den der Test meint: ein
    # gueltiger Schluessel liegt vor, das TOKEN ist das Kaputte. Der Fall "Key fehlt"
    # gehoert nicht hierher -- er hat seinen eigenen Test.
    encrypt("egal")  # legt einen gueltigen Key an
    with pytest.raises(DecryptionError):
        decrypt("enc:vollkommen-kaputtes-token")


def test_decrypt_wrong_key_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # FALSCHER Key -- ein ANDERER, VORHANDENER Key, nicht ein fehlender.
    #
    # ANPASSUNG (Befund 65, Aufgabe 10): der Test wechselte frueher nur den Key-Ort und
    # verliess sich darauf, dass ``decrypt`` dort still einen NEUEN Key erzeugt. Er lief
    # damit durch genau die Neuerzeugung, die dieser Befund abschafft -- er mass "Key
    # fehlt", nannte sich aber "wrong key". Gemessen (S85-A9, IST-Lauf): am neuen Ort
    # entstand eine Key-Datei, und der Fehler hiess irrefuehrend "Token ungueltig oder
    # falscher Schluessel". Nach der Aenderung kaeme dort ``KeyMissingError`` -- er waere
    # also nur noch aus Versehen gruen bzw. rot.
    #
    # Der Test stellt jetzt her, was sein Name sagt: am zweiten Ort liegt ein ECHTER,
    # gueltiger Fremd-Key (per ``encrypt`` dort erzeugt). Das Token des ersten Orts trifft
    # damit auf einen vorhandenen, aber falschen Schluessel -> DecryptionError. Der Fall
    # "Key fehlt" hat seinen eigenen Test (test_decrypt_missing_key_file_*).
    cipher = encrypt("geheim")

    zweiter_ort = tmp_path / "anderer_ort"
    monkeypatch.setenv("CERNIS_DATA_DIR", str(zweiter_ort))
    encrypt("egal")  # legt am zweiten Ort einen eigenen, gueltigen Key an
    assert (zweiter_ort / "secret_cipher.key").exists()

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


# ── Befund 65: der LESEVERSUCH darf den Schluessel NICHT erzeugen ────────────


def test_decrypt_missing_key_file_raises_and_creates_nothing() -> None:
    # DER KERN VON BEFUND 65. Verschluesseln, Schluesseldatei loeschen, entschluesseln:
    #
    # 1. Der Fehler ist BENANNT (KeyMissingError -- "Datei fehlt"), nicht der bisherige
    #    irrefuehrende DecryptionError ("Token ungueltig oder falscher Schluessel").
    # 2. UND -- der eigentliche Punkt -- die Schluesseldatei darf danach NICHT existieren.
    #    Vorher legte der Lesepfad hier still einen neuen Key an: das vorhandene Chiffrat
    #    wurde damit dauerhaft unlesbar, und der Vorgang, der den Verlust haette melden
    #    koennen, vollzog ihn. Der zweite assert ist der Test.
    key_file = default_key_file()
    cipher = encrypt("geheim")
    assert key_file.exists()

    key_file.unlink()

    with pytest.raises(KeyMissingError) as excinfo:
        decrypt(cipher)

    assert not key_file.exists(), "decrypt hat den Schluessel neu erzeugt -- Verlust vollzogen"
    # Der erwartete Pfad haengt an der Ausnahme, damit der Rand ihn nennen kann,
    # ohne den Meldungstext zu parsen.
    assert excinfo.value.key_file == key_file


def test_key_missing_error_is_key_access_error() -> None:
    # Subtyp-Vertrag: wer breit KeyAccessError/CipherError faengt, sieht den neuen
    # Fall unveraendert; wer den Verlustfall gesondert behandeln will, faengt den Subtyp.
    assert issubclass(KeyMissingError, KeyAccessError)
    assert issubclass(KeyMissingError, CipherError)


def test_decrypt_missing_key_does_not_create_the_data_dir() -> None:
    # Der Lesepfad legt auch das VERZEICHNIS nicht an -- er erzeugt gar nichts.
    key_file = default_key_file()
    with pytest.raises(KeyMissingError):
        decrypt("enc:irgendein-token")
    assert not key_file.exists()
    assert not key_file.parent.exists()


def test_encrypt_still_creates_key_on_first_use() -> None:
    # Gegenprobe zu Befund 65 (Aufgabe 8): der SCHREIBweg darf weiterhin erzeugen --
    # wer verschluesselt, beginnt legitim. Nur der Lesepfad ist eingeschraenkt.
    key_file = default_key_file()
    assert not key_file.exists()

    cipher = encrypt("geheim")

    assert key_file.exists(), "encrypt muss beim Erstgebrauch weiterhin einen Key anlegen"
    assert decrypt(cipher) == "geheim"


def test_decrypt_touches_no_key_file_before_prefix_check() -> None:
    # Aufgabe 3: ein leerer Wert und ein Wert OHNE enc:-Praefix duerfen ueberhaupt nicht
    # zum Schluesselzugriff fuehren -- die Praefix-Pruefung kommt VOR dem Laden. Sonst
    # koennte schon ein unsinniger Eingabewert einen Schluessel anlegen (bzw. jetzt: den
    # Verlustfehler ausloesen, obwohl gar kein Chiffrat im Spiel ist).
    key_file = default_key_file()

    assert decrypt("") == ""
    assert not key_file.parent.exists()

    with pytest.raises(DecryptionError):
        decrypt("plaintext-ohne-praefix")
    assert not key_file.parent.exists()


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
