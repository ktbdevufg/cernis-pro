"""Application-Exceptions der export-Use-Cases.

Eigene Fehlerklasse OHNE HTTP-Details -- das Mapping auf Statuscodes passiert am Rand
(api/Composition Root). Die Basisklasse folgt dem Projektmuster (scanning/devices/
diagnostics/analysis fuehren je eine ``*ApplicationError``-Basis) und dient als gemeinsamer
Aufhaenger der export-Use-Cases.

``ScanNotFoundError`` benennt den Fall "die angefragte ``scan_id`` existiert nicht in der
ScanHistory". Anders als die diagnostics-Tool-fehlt-/Dienst-Naht (eine infra-EIGENE
Exception, weil der Adapter den Ausfall erkennt) ist DIES ein reiner APPLICATION-Zustand:
der ``scan_provider`` liefert ``None`` und der Use-Case uebersetzt das in diese Exception.
Der api-Rand bildet sie auf **404** ab (Muster ``DeviceNotFoundError`` -- das HTTP-Detail
bleibt am Rand, die Exception traegt nur die neutrale Bedeutung).
"""


class ExportApplicationError(Exception):
    """Basis fuer Fehler der export-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class ScanNotFoundError(ExportApplicationError):
    """Die angefragte ``scan_id`` existiert nicht in der ScanHistory (Block 1).

    Reiner APPLICATION-Zustand: der ``scan_provider`` lieferte ``None`` (kein Scan zu dieser
    ID). Der Use-Case wirft diese Exception statt eines stillen leeren Exports (ADR 0001:
    kein stiller Fallback -- eine nicht existierende ID ist ein Fehler, kein leerer Bericht).
    Der api-Rand bildet sie auf **404** ab (Muster ``DeviceNotFoundError``); das HTTP-Detail
    bleibt am Rand, die Exception traegt nur die neutrale Bedeutung.
    """

    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        super().__init__(f"Scan {scan_id} wurde nicht gefunden.")


class LoggingReportNotFound(ExportApplicationError):
    """Die angefragte ``task_id`` hat keine Logging-Aufgabe (Block 3).

    Reiner APPLICATION-Zustand (Muster ``ScanNotFoundError``): der ``logging_report_provider``
    lieferte ``None`` (kein Task zu dieser id). Der Use-Case wirft diese Exception statt eines
    stillen leeren Exports (ADR 0001: kein stiller Fallback -- eine nicht existierende id ist
    ein Fehler, kein leerer Bericht). Der api-Rand bildet sie auf **404** ab (eigener globaler
    Handler im Composition Root, Muster ``ScanNotFoundError`` -> 404).

    EIGENER Fehler in ``application/export`` (NICHT die bestehende
    ``application.monitoring.LoggingTaskNotFound``): der Export-Use-Case bleibt damit frei von
    einer Kopplung an ein anderes application-Modul -- symmetrisch zu ``ScanNotFoundError``
    (der Scan-Export importiert auch keine scanning-Application). Die ``task_id`` ist ein
    dateinamen-tauglicher Hex-String; sie wird im Fehler mitgefuehrt, damit er ohne
    Kontext-Rekonstruktion sprechend ist.
    """

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__(f"Logging-Aufgabe {task_id} wurde nicht gefunden.")
