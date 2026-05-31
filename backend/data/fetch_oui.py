#!/usr/bin/env python3
"""Download and parse IEEE OUI database for MAC vendor lookup."""
import urllib.request
import json
import os
import re

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUTPUT = os.path.join(os.path.dirname(__file__), "oui.json")


def fetch_and_parse():
    print("Downloading OUI database from IEEE...")
    try:
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "LANScan/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Download failed: {e}")
        print("Using fallback minimal OUI database...")
        return _fallback()

    oui_map = {}
    for line in raw.splitlines():
        m = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line.strip())
        if m:
            prefix = m.group(1).replace("-", "").upper()
            vendor = m.group(2).strip()
            oui_map[prefix] = vendor

    with open(OUTPUT, "w") as f:
        json.dump(oui_map, f)
    print(f"OUI database saved: {len(oui_map)} entries -> {OUTPUT}")
    return oui_map


def _fallback():
    """Minimal fallback with common vendors."""
    oui_map = {
        "B072BF": "AVM Audiovisuelles Marketing",
        "DC8B28": "Apple Inc.",
        "3C22FB": "Apple Inc.",
        "A4C3F0": "Apple Inc.",
        "00005E": "IANA",
        "00000C": "Cisco Systems",
        "000050": "Radisys",
        "0000F0": "Samsung Electronics",
        "B827EB": "Raspberry Pi Foundation",
        "DCA632": "Raspberry Pi Foundation",
        "E45F01": "Raspberry Pi Foundation",
        "001B21": "Intel Corporate",
        "0026B9": "Dell Inc.",
        "48F17F": "Intel Corporate",
        "6C4008": "Logitech",
        "0040AB": "CNET Technology",
        "000C29": "VMware Inc.",
        "001C42": "Parallels Inc.",
        "080027": "PCS Systemtechnik GmbH",
    }
    with open(OUTPUT, "w") as f:
        json.dump(oui_map, f)
    print(f"Fallback OUI database saved: {len(oui_map)} entries")
    return oui_map


if __name__ == "__main__":
    fetch_and_parse()
