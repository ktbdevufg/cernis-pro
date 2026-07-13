"""Symmetrische Verschluesselung fuer at-rest gespeicherte Geheimnisse (Fernet).

Ersetzt den Altcode ``modules/crypto.py``. Leitprinzip (ADR 0001): KEIN stiller
Fallback. Verschluesseln gelingt -- oder es wirft. Ein Geheimnis (z. B. ein
SMTP-Passwort) darf unter KEINEN Umstaenden unverschluesselt gespeichert werden.
Ein Leerzustand (leerer Klartext) ist gueltig und ehrlich; jeder andere Fehler wird
benannt und niemals verschluckt.

Vertrag im Ueberblick
---------------------
* ``encrypt(plaintext)``  -> Cipher mit dem Praefix ``enc:``. Leerer Klartext ergibt
  ``""`` (gueltiger Leerzustand). Bei JEDEM anderen Problem wird geworfen -- es gibt
  KEINEN Rueckgabepfad, der Klartext liefert.
* ``decrypt(cipher)``     -> Klartext. Leerer Eingabewert ergibt ``""``. Jeder
  nicht-leere Wert OHNE ``enc:``-Praefix ist ungueltig und wirft ``DecryptionError``
  (kein Klartext-Durchreichpfad, keine Altbestand-Ausnahme). Ein Wert MIT Praefix,
  der sich nicht entschluesseln laesst, wirft ebenfalls ``DecryptionError`` --
  ``decrypt`` gibt NIEMALS ``""`` zurueck, um einen Fehler zu verbergen.
* ``is_encrypted(value)`` -> ``True`` genau dann, wenn ``value`` das Praefix traegt.

``cryptography`` ist harte Pflicht (steht in ``pyproject.toml``). Es gibt KEIN
Verfuegbarkeits-Flag, KEINEN base64-Zweig, KEINE Ersatzverschluesselung. Fehlt die
Bibliothek, ist die Installation kaputt -- der ``ImportError`` schlaegt beim Laden
dieses Moduls hart durch, statt still auf Kodierung auszuweichen.

Schluesselverwaltung
--------------------
Ein Fernet-Schluessel wird beim ersten Gebrauch erzeugt und in einer Datei im
Benutzer-Datenverzeichnis abgelegt (siehe ``default_key_file`` fuer die kanonische
Pfadwahl). Bei JEDEM Zugriff werden auf POSIX die Rechte durchgesetzt: die Datei
0600, ihr Verzeichnis 0700 (der Altcode setzte sie nur beim Erzeugen). Ein bereits
vorhandener Schluessel wird wiederverwendet, niemals ueberschrieben.

Auf Windows sind POSIX-Rechte (``chmod``/``mkdir(mode=...)``) weitgehend
WIRKUNGSLOS -- NTFS-ACLs richten sich nicht danach. Dieses Modul tut daher NICHT so,
als schuetze es die Schluesseldatei dort; die ``chmod``-Aufrufe sind auf POSIX
beschraenkt und auf Windows bewusst weggelassen. Der Schutz der Datei unter Windows
haengt an den geerbten Verzeichnis-ACLs des Benutzerprofils, nicht an diesem Code.

Import-linter-konform
---------------------
Dieses Modul importiert ausschliesslich stdlib + ``cryptography`` (kein
``modules``-Bezug). Die kanonische Pfad-Logik ist hier stdlib-nur nachgebildet --
analog zu ``infrastructure/bundle_paths.py`` -- und trifft dieselbe kanonische
Datenverzeichnis-Wahl wie ``modules/db_path.get_data_dir`` (``CERNIS_DATA_DIR`` bzw.
Plattform-Default), OHNE den Altcode-Ring zu importieren. Damit haelt der Adapter den
Contract "neue Ringe importieren NICHT den Altcode" ein.
"""

import os
import platform
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# Praefix, das einen verschluesselten Wert kennzeichnet. Ein Wert mit diesem Praefix
# ist ein Cipher; ein nicht-leerer Wert ohne dieses Praefix ist ungueltig.
_PREFIX = "enc:"

# Dateiname der Schluesseldatei innerhalb des Benutzer-Datenverzeichnisses.
_KEY_FILENAME = "secret_cipher.key"


class CipherError(Exception):
    """Gemeinsame Basis aller Ausnahmen dieses Moduls.

    Der Aufrufer kann breit ``CipherError`` fangen oder ueber die beiden Subtypen
    (``KeyAccessError`` / ``DecryptionError``) feiner unterscheiden.
    """


class KeyAccessError(CipherError):
    """Der Schluessel konnte nicht gelesen ODER geschrieben werden.

    Deckt fehlendes Schreibrecht auf dem Verzeichnis, unlesbaren/leeren
    Schluesselinhalt und jeden anderen Datei-/OS-Fehler beim Schluesselzugriff ab. Ein
    solcher Fehler ist ein Fehler -- NIE ein stiller Rueckfall auf Klartext.
    """


class DecryptionError(CipherError):
    """Entschluesselung fehlgeschlagen -- ungueltiger/fehlender Praefix oder kaputtes Token.

    ``decrypt`` wirft diese Ausnahme, statt einen leeren String zurueckzugeben, um den
    Fehler zu verbergen (das war der Altcode-S3-Bug).
    """


def default_key_file() -> Path:
    """Kanonischer Pfad der Schluesseldatei: ``<data_dir>/secret_cipher.key``.

    ``<data_dir>`` ist dasselbe Benutzer-Datenverzeichnis, das der Rest der App fuer
    ``cernis.db`` u. a. nutzt (identische Wahl wie ``modules/db_path.get_data_dir``):

    1. ``CERNIS_DATA_DIR`` (vom Swift/Electron-Wrapper gesetzt), falls vorhanden.
    2. macOS ``.app``-Bundle -> ``~/Library/Application Support/de.cernis.pro/``.
    3. Windows -> ``%APPDATA%/CernisPro/``.
    4. Linux -> ``$XDG_DATA_HOME`` bzw. ``~/.local/share/cernis-pro/``.
    5. Entwicklung/Fallback -> ``<backend>/data/``.

    BEGRUENDUNG der Pfadwahl: Der Altcode hatte drei divergente Orte -- ``crypto.py``
    nutzte ``~/.cernis-pro/keyring``, das ungenutzte ``db_path.get_keyring_path``
    lieferte ``~/.cernis/keyring``, und die Daten selbst lagen unter
    ``get_data_dir()``. Diese Divergenz war Teil des Problems. v2 waehlt EINEN Ort:
    das kanonische Datenverzeichnis, in dem bereits ``cernis.db`` liegt. So teilt der
    Schluessel das Schicksal der Datenbank (dieselbe Backup-/Loesch-Einheit) und es
    gibt keinen verwaisten zweiten Geheimnis-Ort mehr. Rueckwaertskompatibilitaet zum
    alten Schluesselort ist NICHT gefordert (gruene Wiese).

    Nur stdlib -- kein ``modules``-Import (Import-linter-Contract). Die Logik ist eine
    bewusste Spiegelung von ``db_path.get_data_dir`` an der Ring-Grenze.
    """
    return _data_dir() / _KEY_FILENAME


def _data_dir() -> Path:
    """Loest das Benutzer-Datenverzeichnis auf (stdlib-nur Spiegel von db_path)."""
    env_dir = os.environ.get("CERNIS_DATA_DIR", "")
    if env_dir:
        return Path(env_dir)

    exe = Path(sys.executable).resolve()
    is_bundle = any("CernisPro.app" in str(p) for p in [exe, *exe.parents])
    if is_bundle:
        return Path.home() / "Library" / "Application Support" / "de.cernis.pro"

    system = platform.system()
    if system == "Windows":
        app_data = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(app_data) / "CernisPro"
    if system == "Linux":
        xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        return Path(xdg) / "cernis-pro"

    # Entwicklung/Fallback: <backend>/data/ -- dieses Modul liegt unter
    # backend/infrastructure/crypto/, also drei Ebenen ueber "data".
    return Path(__file__).resolve().parent.parent.parent / "data"


def _is_posix() -> bool:
    """``True`` auf POSIX-Systemen (Linux/macOS), wo ``chmod`` wirksam ist."""
    return os.name == "posix"


def _enforce_permissions(key_dir: Path, key_file: Path) -> None:
    """Erzwingt 0700 aufs Verzeichnis und 0600 auf die Datei -- POSIX-only.

    Wird bei JEDEM Zugriff aufgerufen (nicht nur beim Erzeugen), damit ein zu lax
    angelegter Schluessel aus einem frueheren Lauf oder von aussen korrigiert wird.
    Auf Windows ein bewusstes No-op (POSIX-Rechte sind dort wirkungslos).
    """
    if not _is_posix():
        return
    os.chmod(key_dir, 0o700)
    os.chmod(key_file, 0o600)


def _get_or_create_key(key_file: Path) -> bytes:
    """Laedt den vorhandenen Schluessel oder erzeugt ihn beim ersten Gebrauch.

    Wirft ``KeyAccessError`` bei JEDEM Datei-/OS-Problem (kein stiller Fallback). Ein
    vorhandener Schluessel wird wiederverwendet und NIE ueberschrieben. Rechte werden
    bei jedem Aufruf durchgesetzt (POSIX).
    """
    key_dir = key_file.parent
    try:
        key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        if key_file.exists():
            key = key_file.read_bytes().strip()
            if not key:
                # Leere/kaputte Schluesseldatei ist ein Fehler, kein Neuanlege-Anlass:
                # ein Ueberschreiben wuerde bestehende Cipher unlesbar machen, OHNE
                # dass der Nutzer es merkt. Ehrlich scheitern.
                raise KeyAccessError(f"Schluesseldatei leer oder unlesbar: {key_file}")
            _enforce_permissions(key_dir, key_file)
            return key

        # Erstgebrauch: neuen Schluessel erzeugen und atomar-genug ablegen.
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        _enforce_permissions(key_dir, key_file)
        return key
    except KeyAccessError:
        raise
    except OSError as exc:
        # Verzeichnis nicht anlegbar/beschreibbar, Datei nicht schreib-/lesbar, ...
        raise KeyAccessError(f"Schluesselzugriff fehlgeschlagen: {key_file} ({exc})") from exc


def encrypt(plaintext: str) -> str:
    """Verschluesselt ``plaintext`` und liefert den Cipher mit ``enc:``-Praefix.

    Leerer Klartext ergibt ``""`` (gueltiger Leerzustand, kein Fehler). Bei JEDEM
    anderen Problem -- Schluessel nicht zugreifbar, Krypto-Fehler -- wird geworfen
    (``KeyAccessError`` bzw. ``CipherError``). Es gibt KEINEN Rueckgabepfad, der
    Klartext liefert: ein unverschluesseltes Geheimnis darf nicht in die DB gelangen.
    """
    if not plaintext:
        return ""

    key = _get_or_create_key(default_key_file())
    try:
        token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    except Exception as exc:
        # Breit gefangen mit ABSICHT: kein stiller Klartext-Fallback -- jeder Fehler
        # beim Verschluesseln wird als CipherError benannt, nie in Klartext verwandelt.
        raise CipherError(f"Verschluesselung fehlgeschlagen: {exc}") from exc
    return _PREFIX + token.decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Entschluesselt einen mit ``encrypt`` erzeugten Cipher und liefert den Klartext.

    Leerer Eingabewert ergibt ``""``. Ein nicht-leerer Wert OHNE ``enc:``-Praefix ist
    ungueltig und wirft ``DecryptionError`` (kein Klartext-Durchreichpfad, keine
    Altbestand-Ausnahme). Ein Wert MIT Praefix, der sich nicht entschluesseln laesst
    (kaputtes/fremdes Token, falscher Schluessel), wirft ebenfalls ``DecryptionError``
    -- NIEMALS wird ``""`` zurueckgegeben, um einen Fehler zu verbergen.
    """
    if not ciphertext:
        return ""

    if not is_encrypted(ciphertext):
        raise DecryptionError("Wert traegt kein enc:-Praefix -- kein gueltiger Cipher")

    key = _get_or_create_key(default_key_file())
    token = ciphertext[len(_PREFIX) :].encode("ascii")
    try:
        return Fernet(key).decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError("Token ungueltig oder falscher Schluessel") from exc
    except Exception as exc:
        # Breit gefangen mit ABSICHT: jeder Krypto-/Dekodier-Fehler ist ein Fehler,
        # kein stilles "" (das war der Altcode-S3-Bug, der Fehler verbarg).
        raise DecryptionError(f"Entschluesselung fehlgeschlagen: {exc}") from exc


def is_encrypted(value: str) -> bool:
    """``True`` genau dann, wenn ``value`` das ``enc:``-Praefix traegt."""
    return value.startswith(_PREFIX)
