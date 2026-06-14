"""Adapter-eigene Fehler der sni-Infrastructure.

``SniError`` ist die EINE Fehlerklasse, die der SNI-Sniffer nach aussen wirft, wenn
der Sniff beim Start scheitert (toter Sniffer-Thread nach der Alive-Probe --
typischerweise fehlendes ``CAP_NET_RAW``/Geraet weg, oder scapy nicht verfuegbar).
Muster ``infrastructure.capture.errors.CaptureError``: bewusst kein Durchreichen der
scapy-Roh-Exception in die Ringe (Port-Vertrag: "ein Permission-/Start-Fehler ist ein
FEHLER", aber ein DOMAENEN-/Adapter-Fehler, kein scapy-Leck). KEIN stilles Leer-
Erfassen (S3). Der Composition Root mappt ``SniError`` auf eine ehrliche 503 (Muster
``DiagnosticsToolMissing``/``ResolverToolMissing``); der regulaere Permission-Fall
geht ueber die ``StartSni``-``{ok,error}``-Naht und wird zur 403, bevor ueberhaupt
gestartet wird.
"""


class SniError(Exception):
    """SNI-Sniff konnte nicht gestartet/fortgesetzt werden (z. B. Rechte/Geraet/scapy)."""
