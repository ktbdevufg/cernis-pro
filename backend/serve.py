"""CERNIS PRO - Prozess-Einstiegspunkt fuer app:app (ADR-0004 P.3).

Loest main.py als Entry-Point ab. Enthaelt KEINE Logik ausser
Prozess-Start: Port/Host-Behandlung (analog main.py) und das generelle
Setzen des Bootstrap-Flags (frozen wie dev), BEVOR app importiert wird.
"""

from __future__ import annotations

import os
import sys


def _is_frozen() -> bool:
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def main() -> None:
    # serve.py ist immer ein echter Prozessstart (kein Test), darum wird das
    # Bootstrap-Flag hier generell gesetzt - frozen wie dev -, BEVOR app
    # importiert wird (AppConfig() liest CERNIS_BOOTSTRAP_ON_STARTUP beim
    # App-Bau frisch aus der Umgebung). setdefault laesst eine extern gesetzte
    # Variable (z. B. CERNIS_BOOTSTRAP_ON_STARTUP=false) weiterhin Vorrang.
    # Tests bauen die App direkt ueber create_app()/AppConfig() und sind nicht
    # betroffen (Doppelstart-/Test-Schutz bleibt erhalten).
    os.environ.setdefault("CERNIS_BOOTSTRAP_ON_STARTUP", "true")

    import uvicorn

    port = int(os.environ.get("CERNIS_PORT", "8765"))
    host = "127.0.0.1"

    if _is_frozen():
        from app import app

        uvicorn.run(app, host=host, port=port, reload=False, log_level="info")
    else:
        uvicorn.run("app:app", host=host, port=port, reload=False, log_level="info")


if __name__ == "__main__":
    main()
