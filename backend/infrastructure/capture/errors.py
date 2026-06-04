"""Adapter-eigene Fehler der capture-Infrastructure.

``CaptureError`` ist die EINE Fehlerklasse, die der Capture-Strom nach aussen
wirft, wenn der Sniffer beim Start scheitert (toter Sniffer-Thread nach der
Alive-Probe -- typischerweise fehlendes ``CAP_NET_RAW``/Geraet weg). Bewusst kein
Durchreichen der scapy-Roh-Exception (Port-Vertrag: "ein Permission-/Geraete-
Fehler beim Start ist ein FEHLER", aber ein DOMAENEN-/Adapter-Fehler, nicht ein
scapy-Leck in die Ringe). KEIN stilles Leer-Iterieren (S3).
"""


class CaptureError(Exception):
    """Capture konnte nicht gestartet/fortgesetzt werden (z. B. Rechte/Geraet)."""
