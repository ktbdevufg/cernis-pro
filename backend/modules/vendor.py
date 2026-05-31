"""MAC address to vendor lookup using local OUI database."""
import json
import os
import re
from functools import lru_cache

_oui_db: dict | None = None


def _find_oui_db() -> str:
    """Find oui.json — handles PyInstaller bundle, macOS app, and dev mode."""
    import sys
    candidates = []

    # PyInstaller frozen: binary in cernis-backend/, data in _internal/data/ or nearby
    if hasattr(sys, '_MEIPASS'):
        candidates += [
            os.path.join(sys._MEIPASS, "data", "oui.json"),
            os.path.join(sys._MEIPASS, "oui.json"),
            os.path.join(os.path.dirname(sys.executable), "data", "oui.json"),
            os.path.join(os.path.dirname(sys.executable), "..", "data", "oui.json"),
        ]

    # Script / venv mode
    candidates += [
        os.path.join(os.path.dirname(__file__), "../data/oui.json"),
        os.path.join(os.path.dirname(__file__), "../../data/oui.json"),
    ]

    for p in candidates:
        resolved = os.path.realpath(p)
        if os.path.exists(resolved):
            return resolved
    return ""


def _load_db() -> dict:
    global _oui_db
    if _oui_db is None:
        path = _find_oui_db()
        if path and os.path.exists(path):
            with open(path) as f:
                _oui_db = json.load(f)
        else:
            _oui_db = {}
    return _oui_db


@lru_cache(maxsize=4096)
def lookup_vendor(mac: str) -> str:
    """Return vendor name for a MAC address, or empty string if unknown."""
    if not mac:
        return ""
    # Normalize: remove separators, uppercase, take first 6 chars
    clean = re.sub(r"[:\-\.]", "", mac).upper()
    if len(clean) < 6:
        return ""
    prefix = clean[:6]
    db = _load_db()
    return db.get(prefix, "")


def reload():
    """Reload OUI database from disk."""
    global _oui_db
    _oui_db = None
    lookup_vendor.cache_clear()
    _load_db()
