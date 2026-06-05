"""CERNIS PRO - Prozess-Einstiegspunkt fuer app:app (ADR-0004 P.3).

Loest main.py als Entry-Point ab. Enthaelt KEINE Logik ausser
Prozess-Start: Port/Host-Behandlung (analog main.py) und das Setzen
des Bootstrap-Flags im frozen-Fall, BEVOR app importiert wird.
"""

from __future__ import annotations

import os
import sys


def _is_frozen() -> bool:
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def main() -> None:
    # Frozen (Produktiv-Bundle): Bootstrap erzwingen, BEVOR app importiert
    # wird - AppConfig() liest CERNIS_BOOTSTRAP_ON_STARTUP beim App-Bau frisch
    # aus der Umgebung. Im dev-Fall bewusst NICHT setzen (Doppelstart-/Test-Schutz).
    if _is_frozen():
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
