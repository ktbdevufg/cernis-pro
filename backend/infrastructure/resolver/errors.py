"""Infrastruktur-eigene Exceptions der resolver-Adapter."""


class ResolverToolMissing(Exception):
    """Ein benoetigtes System-Binary (``dig``) fehlt -- infra-eigen.

    Vorbild ``infrastructure.diagnostics_linux.DiagnosticsToolMissing``: eine
    infrastruktur-eigene Exception, die der Composition Root (``app.py``) auf einen
    HTTP-Fehler abbildet. ``tool`` ist der Name des fehlenden Binaries; ``message`` die
    neutrale, nutzerseitige Meldung (KEIN distro-spezifischer Install-Befehl -- das ist
    Sache eines spaeteren Blocks).
    """

    def __init__(self, tool: str) -> None:
        self.tool = tool
        self.message = f"Programm '{tool}' wurde nicht gefunden."
        super().__init__(self.message)


class ResolverDataMissing(Exception):
    """Eine benoetigte lokale Datendatei (Geo/ASN-CSV) fehlt -- infra-eigen.

    Gleiches Muster wie ``ResolverToolMissing``, aber fuer eine fehlende DATEN-Datei
    statt eines fehlenden Binaries. BEWUSST kein stiller Leer-Fallback (kein ``{}`` wie
    ``modules.vendor._load_db``): eine fehlende Geo/ASN-DB ist ein echter
    Konfigurationsfehler und soll sichtbar werden, nicht jeden Lookup still leeren.
    ``path`` ist der Pfad der fehlenden Datei; ``message`` die neutrale, nutzerseitige
    Meldung. Der Composition Root (``app.py``) bildet sie spaeter auf einen HTTP-Fehler
    ab (eigener Teilschritt, NICHT hier).
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.message = f"Datendatei '{path}' wurde nicht gefunden."
        super().__init__(self.message)
