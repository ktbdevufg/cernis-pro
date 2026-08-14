"""CERNIS PRO - Prozess-Einstiegspunkt fuer app:app (ADR-0004 P.3).

Loest main.py als Entry-Point ab. Enthaelt KEINE Logik ausser
Prozess-Start: Port/Host-Behandlung (analog main.py), das generelle
Setzen des Bootstrap-Flags (frozen wie dev), BEVOR app importiert wird,
und die Startverweigerung bei unbrauchbarem Datenbank-Schema (S88-P1a).
"""

from __future__ import annotations

import os
import sys

import structlog

logger = structlog.get_logger()

# Rueckgabewert bei verweigertem Start wegen des Datenbank-Schemas (S88-P1a): die
# Datenbank stammt aus einer neueren Programmfassung, oder eine Migration ist
# gescheitert. Ein eigener Wert (nicht 1), damit der aufrufende Wrapper diesen Fall
# von einem gewoehnlichen Absturz unterscheiden kann.
EXIT_SCHEMA_UNBRAUCHBAR = 105


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

    from infrastructure.db_schema import SchemaMigrationError, SchemaTooNewError

    port = int(os.environ.get("CERNIS_PORT", "8765"))
    host = "127.0.0.1"

    # Startverweigerung bei unbrauchbarem Schema (S88-P1a, Aufgabe 3). Der Ort ist
    # BEWUSST serve.py und nicht app.py: app.py wird auch von Tests gebaut, und ein
    # Testlauf darf keinen Prozess beenden -- ``create_app`` laesst die Ausnahme
    # darum nach aussen, und erst hier, im echten Prozessstart, wird daraus ein
    # Rueckgabewert.
    #
    # Nachgemessen, dass beide Wege die Ausnahme ueberhaupt sehen koennen: im
    # frozen-Weg laeuft ``from app import app`` direkt in dieser Funktion (der
    # Modul-Level-``create_app()`` in app.py wirft beim Import). Im dev-Weg importiert
    # uvicorn das Modul selbst -- gemessen mit einem Wegwerf-Modul, das beim Import
    # wirft: ``uvicorn.run("app:app", ...)`` reicht die Ausnahme unveraendert an den
    # Aufrufer durch. Das try umschliesst darum beide Wege.
    #
    # Kein Traceback nach aussen, nur eine klare Protokollzeile. Die ANZEIGE beim
    # Anwender ist NICHT Teil dieses Auftrags -- hier entstehen ausschliesslich der
    # Rueckgabewert und die Protokollzeile.
    try:
        if _is_frozen():
            from app import app

            uvicorn.run(app, host=host, port=port, reload=False, log_level="info")
        else:
            uvicorn.run("app:app", host=host, port=port, reload=False, log_level="info")
    except SchemaTooNewError as fehler:
        logger.error(
            "start_verweigert_schema_zu_neu",
            gelesene_fassung=fehler.gelesene_fassung,
            erwartete_fassung=fehler.erwartete_fassung,
        )
        raise SystemExit(EXIT_SCHEMA_UNBRAUCHBAR) from None
    except SchemaMigrationError as fehler:
        logger.error(
            "start_verweigert_schema_migration",
            gelesene_fassung=fehler.gelesene_fassung,
            erwartete_fassung=fehler.erwartete_fassung,
            sicherung=str(fehler.sicherung_pfad) if fehler.sicherung_pfad else None,
            grund=fehler.grund,
        )
        raise SystemExit(EXIT_SCHEMA_UNBRAUCHBAR) from None


if __name__ == "__main__":
    main()
