"""Krypto-Infrastruktur-Adapter der v2-Architektur.

Enthaelt ``secret_cipher`` -- symmetrische Verschluesselung fuer at-rest gespeicherte
Geheimnisse (Fernet), mit einem lokal verwalteten Schluessel im Benutzer-Datenverzeichnis.
Ersetzt den Altcode ``modules/crypto.py``, der Sicherheit als graduelle Groesse mit
stillen Rueckfallebenen behandelte (ADR 0001 -- keine stillen Fallbacks).
"""

from infrastructure.crypto.secret_cipher import (
    CipherError,
    DecryptionError,
    KeyAccessError,
    decrypt,
    encrypt,
    is_encrypted,
)

__all__ = [
    "CipherError",
    "DecryptionError",
    "KeyAccessError",
    "decrypt",
    "encrypt",
    "is_encrypted",
]
