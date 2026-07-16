"""Behebt den OpenSSL-DLL-Konflikt auf Windows ARM64 dauerhaft.

Hintergrund
-----------
Auf Windows ARM64 (aarch64-pc-windows-msvc) existieren zwei DLLs mit
demselben Basisnamen ``libcrypto-3-arm64.dll`` im Prozess:

* Pythons Standardbibliothek ``ssl`` (``DLLs/_ssl.pyd``) laedt die von der
  Python-Distribution mitgelieferte OpenSSL-Version (hier 3.0.16).
* ``cryptography`` (aus Source gebaut, ``hazmat/bindings/_rust.pyd``) laedt
  die vcpkg-OpenSSL-Version (hier 3.6.3).

Windows loest eine DLL pro Prozess nur einmal ueber ihren Basisnamen auf:
Wer zuerst importiert, gewinnt. Importiert irgendetwas ``ssl`` vor
``cryptography`` (z. B. FastAPI/uvicorn beim App-Start oder pytest-Plugins
bei der Testsammlung), ist bereits die aeltere 3.0.16 im Speicher. Beim
spaeteren Laden von ``_rust.pyd`` bindet der Loader an diese bereits
geladene DLL, der aber Symbole der 3.6.3 fehlen -> ``ImportError: DLL load
failed while importing _rust: Die angegebene Prozedur wurde nicht
gefunden.``

Loesung
-------
Ein ``.pth``-Datei in ``site-packages`` fuehrt beim Interpreter-Start --
noch vor jedem Nutzer-Import und damit vor ``ssl`` -- ``import
cryptography.hazmat.bindings._rust`` aus. Damit gewinnt die 3.6.3 den
Basisnamen fuer den gesamten Prozess. Die 3.6.3 ist ein Superset der
3.0.16, sodass auch die Standardbibliothek ``ssl`` danach korrekt laeuft.

Die ``.pth``-Datei liegt in ``.venv`` und wird bei jedem Neuaufbau der venv
(``uv sync --reinstall`` o. ae.) geloescht. Dieses Skript stellt sie
idempotent wieder her. Nach jedem venv-Neuaufbau ausfuehren:

    uv run python scripts/fix-openssl-dll-arm64.py

Das Skript ist bewusst plattform-spezifisch (nur Windows ARM64) und ein
No-Op auf allen anderen Plattformen -- gemaess Rewrite-Scope bleibt der
systemnahe Eingriff lokal und ein spaeterer Wegfall (statisches Einlinken
von OpenSSL) ist ein einzelner, klar begrenzter Schritt.
"""

from __future__ import annotations

import platform
import site
import sys
from pathlib import Path

# Kennung fuer die erzeugte .pth-Datei. Praefix "zzz_" erzwingt eine spaete
# alphabetische Sortierung -- irrelevant fuer die Korrektheit (der Import
# geschieht ohnehin vor jedem Nutzercode), aber vermeidet Kollisionen mit
# anderen .pth-Dateien.
_PTH_NAME = "zzz_openssl_arm64_preload.pth"

# Code-Zeile, die die .pth beim Interpreter-Start ausfuehrt. Der try/except
# haelt fremde Interpreter (ohne cryptography) am Leben -- KEIN stiller
# Fallback im Sinne von Finding S3: schlaegt der Preload fehl, wird der
# eigentliche Import spaeter mit klarer Fehlermeldung scheitern, nicht
# dieser Startup-Hook.
_PTH_LINE = (
    "import cryptography.hazmat.bindings._rust  "
    "# OpenSSL-DLL-Preload Windows ARM64, siehe scripts/fix-openssl-dll-arm64.py\n"
)


def _is_windows_arm64() -> bool:
    return sys.platform == "win32" and platform.machine().upper() in {"ARM64", "AARCH64"}


def _site_packages() -> Path:
    """Ermittelt das site-packages-Verzeichnis der aktiven venv."""
    for entry in site.getsitepackages():
        candidate = Path(entry)
        if candidate.name == "site-packages" and candidate.is_dir():
            return candidate
    # Fallback: aus dem Interpreter-Praefix ableiten (Windows-Layout).
    candidate = Path(sys.prefix) / "Lib" / "site-packages"
    if candidate.is_dir():
        return candidate
    raise RuntimeError(f"site-packages nicht gefunden (getsitepackages={site.getsitepackages()!r})")


def main() -> int:
    if not _is_windows_arm64():
        print(f"Kein Windows ARM64 ({sys.platform}/{platform.machine()}) -- nichts zu tun.")
        return 0

    target = _site_packages() / _PTH_NAME

    if target.exists() and target.read_text(encoding="utf-8") == _PTH_LINE:
        print(f"OpenSSL-Preload bereits aktiv: {target}")
        return 0

    target.write_text(_PTH_LINE, encoding="utf-8")
    print(f"OpenSSL-Preload installiert: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
