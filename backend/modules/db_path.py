"""
CERNIS PRO — Database Path Resolution
Detects whether running inside a macOS .app bundle and uses
~/Library/Application Support/de.cernis.pro/ accordingly.
All other platforms use the local data/ directory.
"""
import os
import sys
from pathlib import Path


def get_data_dir() -> Path:
    """
    Returns the directory where cernis.db and other data files are stored.

    Priority:
    1. CERNIS_DATA_DIR env variable (set by Swift app)
    2. macOS .app bundle  → ~/Library/Application Support/de.cernis.pro/
    3. Windows            → %APPDATA%/CernisPro/
    4. Linux              → ~/.local/share/cernis-pro/
    5. Development        → <backend>/data/
    """
    # Priority 1: explicit env variable (set by Swift/Electron wrapper)
    env_dir = os.environ.get("CERNIS_DATA_DIR", "")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Detect if running inside a macOS .app bundle
    exe = Path(sys.executable).resolve()
    is_bundle = any("CernisPro.app" in str(p) for p in [exe] + list(exe.parents))

    if is_bundle:
        # macOS App Support
        home = Path.home()
        data_dir = home / "Library" / "Application Support" / "de.cernis.pro"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    import platform
    system = platform.system()

    if system == "Windows":
        app_data = os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")
        data_dir = Path(app_data) / "CernisPro"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    if system == "Linux":
        xdg = os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
        data_dir = Path(xdg) / "cernis-pro"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    # Development / fallback: use local data/ directory
    here = Path(__file__).parent.parent / "data"
    here.mkdir(parents=True, exist_ok=True)
    return here


def get_db_path() -> Path:
    return get_data_dir() / "cernis.db"


def get_keyring_path() -> Path:
    """Keyring stored in ~/.cernis/ always (not in App Support)."""
    p = Path.home() / ".cernis"
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p / "keyring"


# Convenience — usable as string
DATA_DIR = get_data_dir()
DB_PATH  = str(get_db_path())
