#!/usr/bin/env python3
"""Laedt die Geo/ASN-Datenbanken von sapics/ip-location-db (zwei Quellen).

Zwei getrennte, attributionsfreie Quellen, weil keine einzelne CSV der Quelle
Land UND ASN in einer Zeile kombiniert:
  - asn-country  -> Land je IP-Bereich (start,end,country), Lizenz CC0.
  - iptoasn-asn  -> ASN je IP-Bereich (start,end,asn,asn_name), Lizenz Public
                    Domain Dedication v1.0 (attributionsfrei).
Bewusst NICHT das Verzeichnis "asn" — das ist CC BY mit Attributionspflicht.

Anders als fetch_oui.py gibt es hier KEINEN stillen Fallback: eine halbe oder
fehlende DB ist schlimmer als ein lauter Fehler, also wird bei einem
Download-Fehler mit sprechender Meldung abgebrochen.
"""
import os
import urllib.request

RAW_BASE = "https://raw.githubusercontent.com/sapics/ip-location-db/main"
SOURCES = {
    "asn-country-ipv4.csv": f"{RAW_BASE}/asn-country/asn-country-ipv4.csv",
    "asn-country-ipv6.csv": f"{RAW_BASE}/asn-country/asn-country-ipv6.csv",
    "iptoasn-asn-ipv4.csv": f"{RAW_BASE}/iptoasn-asn/iptoasn-asn-ipv4.csv",
    "iptoasn-asn-ipv6.csv": f"{RAW_BASE}/iptoasn-asn/iptoasn-asn-ipv6.csv",
}
DATA_DIR = os.path.dirname(__file__)
TIMEOUT_SECONDS = 60


def _download(url: str) -> bytes:
    """Laedt eine Datei. Wirft bei Fehler eine Exception (kein stiller Fallback)."""
    req = urllib.request.Request(url, headers={"User-Agent": "CERNIS-PRO/2.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return resp.read()


def fetch_all() -> None:
    """Laedt beide CSVs und speichert sie 1:1 neben diesem Skript."""
    for filename, url in SOURCES.items():
        output = os.path.join(DATA_DIR, filename)
        print(f"Lade {filename} von {url} ...")
        try:
            raw = _download(url)
        except Exception as e:
            raise SystemExit(
                f"FEHLER: Download von {url} fehlgeschlagen: {e}. "
                f"Abbruch ohne Fallback — eine halbe Geo/ASN-DB ist schlimmer als keine."
            )
        if not raw:
            raise SystemExit(
                f"FEHLER: {url} lieferte eine leere Antwort. Abbruch ohne Fallback."
            )
        with open(output, "wb") as f:
            f.write(raw)
        line_count = raw.count(b"\n")
        print(f"  gespeichert: {output} ({len(raw)} Bytes, {line_count} Zeilen)")
    print("Fertig: alle vier Geo/ASN-CSVs geladen.")


if __name__ == "__main__":
    fetch_all()
