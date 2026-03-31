"""
CERNIS PRO Secure Credential Storage
Uses Fernet (AES-128-CBC + HMAC-SHA256) for symmetric encryption.
Key is generated once and stored in ~/.cernis/keyring with mode 0600.
"""
import os
import base64
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Key stored in user's home directory, not in project folder
KEY_DIR  = Path.home() / ".pulsar"
KEY_FILE = KEY_DIR / "keyring"


def _get_or_create_key() -> bytes:
    """Load existing key or generate a new one. Stored with 0600 permissions."""
    KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    if KEY_FILE.exists():
        with open(KEY_FILE, "rb") as f:
            return f.read().strip()

    # Generate new key
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)
    return key


def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns base64-encoded ciphertext prefixed with 'enc:'"""
    if not plaintext:
        return ""
    if not HAS_CRYPTO:
        # Fallback: obfuscation only (not secure, but better than plaintext)
        return "b64:" + base64.b64encode(plaintext.encode()).decode()
    try:
        key = _get_or_create_key()
        f = Fernet(key)
        token = f.encrypt(plaintext.encode("utf-8"))
        return "enc:" + token.decode()
    except Exception:
        return plaintext


def decrypt(ciphertext: str) -> str:
    """Decrypt a string encrypted with encrypt(). Returns plaintext."""
    if not ciphertext:
        return ""

    if ciphertext.startswith("b64:"):
        # Obfuscation fallback
        try:
            return base64.b64decode(ciphertext[4:]).decode()
        except Exception:
            return ciphertext

    if not ciphertext.startswith("enc:"):
        # Already plaintext (legacy, before encryption was added)
        return ciphertext

    if not HAS_CRYPTO:
        return ""

    try:
        key = _get_or_create_key()
        f = Fernet(key)
        return f.decrypt(ciphertext[4:].encode()).decode("utf-8")
    except (InvalidToken, Exception):
        return ""


def is_encrypted(value: str) -> bool:
    return value.startswith("enc:") or value.startswith("b64:")
