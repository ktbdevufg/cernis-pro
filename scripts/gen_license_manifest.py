#!/usr/bin/env python3
"""Erzeugt die maschinenlesbare Aufstellung aller mitgelieferten Fremdbestandteile.

Aufruf::

    python scripts/gen_license_manifest.py <ausgabepfad.json>

Das Werkzeug ist eigenstaendig: es importiert nichts aus ``backend`` und kommt mit
der Standardbibliothek aus. Es sammelt die Ebenen ``python``, ``npm``, ``rust``,
``daten`` und ``programme`` und schreibt EINE JSON-Datei. Die Ebene ``nativ`` wird
im Datenformat vorgesehen, aber hier nicht erhoben (siehe ``EBENE_NATIV_HINWEIS``).

Zwei Regeln bestimmen den Aufbau und sind an jeder Sammelstelle einzuhalten:

REGEL 1 -- Vorrang der Paketdatei.
    Der Lizenztext wird immer der Datei entnommen, die das Paket selbst mitbringt.
    Nur wenn keine vorhanden ist, wird auf die Ablage unter ``LICENSES/``
    zurueckgegriffen. Fuer ``GPL-2.0-only`` gilt ausschliesslich die Wurzel-LICENSE
    des Projekts -- die SPDX-Fassung ist gemessen unvollstaendig (ihr fehlt der
    Schlussabsatz), sie wird dort nie verwendet.

REGEL 2 -- Kein Ersatztext.
    Wo weder Paketdatei noch Ablage einen Text liefern, bleibt das Feld ``null`` und
    die zugehoerige Quelle ``nicht_belegt``. Es wird nie der Text eines anderen
    Pakets, ein generischer Text oder eine Platzhalterfassung eingesetzt. Dasselbe
    gilt fuer den Urhebervermerk: die Platzhalter der SPDX-Texte
    (``<year> <copyright holders>``) sind kein Urhebervermerk.

Das Werkzeug faellt kein rechtliches Urteil. Es benennt zu jeder Angabe ihre
Herkunft und kennzeichnet, was nicht belegt ist.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

# --------------------------------------------------------------------------------
# Feste Werte des Datenformats
# --------------------------------------------------------------------------------

SCHEMA_VERSION: Final = "1"

#: Die einzigen zulaessigen Werte der drei Quellenfelder.
QUELLE_PAKETDATEI: Final = "paketdatei"
QUELLE_PAKETMETADATEN: Final = "paketmetadaten"
QUELLE_SPDX_ABLAGE: Final = "spdx_ablage"
QUELLE_WERK_LIZENZ: Final = "werk_lizenz"
QUELLE_REGISTERLISTE: Final = "registerliste"
QUELLE_WERKZEUG_LISTE: Final = "werkzeug_liste"
QUELLE_NICHT_BELEGT: Final = "nicht_belegt"

ZULAESSIGE_QUELLEN: Final = frozenset(
    {
        QUELLE_PAKETDATEI,
        QUELLE_PAKETMETADATEN,
        QUELLE_SPDX_ABLAGE,
        QUELLE_WERK_LIZENZ,
        QUELLE_REGISTERLISTE,
        QUELLE_WERKZEUG_LISTE,
        QUELLE_NICHT_BELEGT,
    }
)

#: Der Bezeichner, fuer den die SPDX-Fassung nie verwendet wird (Regel 1).
GPL2_ONLY: Final = "GPL-2.0-only"

EBENE_NATIV_HINWEIS: Final = (
    "In diesem Schritt nicht erhoben. Die nativen Bibliotheken werden erst aus dem "
    "Bauimage ausgelesen (Arbeitspaket P3b). Die leere Liste bedeutet NICHT, dass "
    "keine nativen Bestandteile mitgeliefert werden."
)

PLATTFORM: Final = "linux-x86_64"
RUST_ZIEL: Final = "x86_64-unknown-linux-gnu"

# --------------------------------------------------------------------------------
# Erkennung von Lizenzdateien und Urhebervermerken
# --------------------------------------------------------------------------------

#: Dateinamen, die als Lizenzdatei eines Pakets in Frage kommen. Bewusst weit
#: gefasst, damit auch die Unterstrich-Form (``LICENSE_MIT``) und ``COPYING``
#: gefunden werden.
LIZENZDATEI_MUSTER: Final = re.compile(
    r"^(LICEN[CS]E|COPYING|NOTICE|LICEN[CS]E[-_.].*|COPYING[-_.].*)$",
    re.IGNORECASE,
)

#: Dateien, die zwar wie eine Lizenzdatei heissen, aber keinen Lizenztext fuehren.
#: ``LICENSE.spdx`` ist ein SPDX-Metadatensatz (Bezeichner und Urhebervermerk,
#: aber kein Wortlaut) -- er darf nach Regel 2 nicht als Lizenztext gelten.
KEIN_LIZENZTEXT_ENDUNG: Final = (".spdx",)

#: Mindestlaenge, ab der eine Datei als Lizenz-Volltext gilt, und die Klauseln, an
#: denen ein echter Lizenzkoerper erkannt wird. Beides folgt den Messregeln aus
#: S71-L3 Block O, damit die erzeugten Zahlen mit der Messung vergleichbar bleiben.
MINDESTLAENGE_VOLLTEXT: Final = 400
MINDESTLAENGE_VOLLTEXT_RUST: Final = 600

KLAUSEL_MUSTER: Final = re.compile(
    r"Permission is hereby granted"
    r"|Redistribution and use"
    r"|Terms and Conditions"
    r"|TERMS AND CONDITIONS"
    r"|Creative Commons Legal Code"
    r"|GNU GENERAL PUBLIC LICENSE"
    r"|GNU LESSER GENERAL PUBLIC LICENSE"
    r"|This is free and unencumbered software"
    r"|Permission to use, copy, modify"
    r"|UNICODE LICENSE"
    r"|Open Data Commons"
    r"|PYTHON SOFTWARE FOUNDATION LICENSE"
    r"|Licensed under the Apache License"
    r"|1\. Definitions",
)

#: Der blosse NAME einer Lizenz ist kein Lizenzkoerper. Eine Datei, die nur auf eine
#: Lizenz verweist ("This Source Code Form is subject to the terms of the Mozilla
#: Public License, v. 2.0"), ist keine Lizenzdatei -- sie als Text auszugeben waere
#: ein Ersatztext im Sinne von Regel 2. Gemessener Anlass: die 989 Zeichen lange
#: certifi-LICENSE beschreibt das CA-Bundle und fuehrt nur einen MPL-Kopfblock,
#: waehrend der MPL-2.0-Volltext 16 727 Zeichen hat.
VERWEIS_MUSTER: Final = re.compile(
    r"This Source Code Form is subject to the terms",
)

#: Derselbe Satz steht aber auch im Anhang ("Exhibit A") des echten MPL-Volltextes.
#: Der Verweis darf deshalb nur dann ausschlagen, wenn die Datei zu kurz ist, um
#: einen Lizenzkoerper zu enthalten. Der kuerzeste hier benoetigte Volltext ist der
#: MIT-Text mit 1 078 Zeichen; die Schwelle liegt bewusst darunter.
VERWEIS_HOECHSTLAENGE: Final = 1000

#: Ein Urhebervermerk ist eine Zeile ``Copyright <Jahr>`` oder ``Copyright <Name>``.
#: Das Wort muss die Zeile eroeffnen -- hoechstens Kommentar- und Aufzaehlungszeichen
#: duerfen davorstehen. Sonst trifft das Muster mitten in den Haftungsausschluss
#: ("...THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM..."), und dessen
#: Bedingungstext ist kein Vermerk.
COPYRIGHT_MUSTER: Final = re.compile(
    r"^[\s#*/;%!\-|>]*(?:Copyright|COPYRIGHT|copyright)\b[\s:]*"
    r"(?:\(c\)|\(C\)|©)?\s*"
    # Danach folgt entweder ein Jahr, ein Name (Grossbuchstabe, @) oder eine
    # Wendung wie "for portions of ... are held by ...". Letztere ist ein echter
    # Vermerk und darf nicht durch die Formforderung verlorengehen.
    r"(?:[0-9]{4}|[A-Z@]|for\b|by\b)",
)

#: Zeilen aus dem Bedingungstext einer Lizenz sind kein Urhebervermerk. Ebenso
#: wenig die Platzhalter der SPDX-Fassungen (Regel 2).
COPYRIGHT_AUSSCHLUSS: Final = re.compile(
    r"The above copyright notice"
    r"|Licensor shall mean the copyright owner"
    r"|applicable copyright doctrines"
    r"|copyright notice(?:s)? (?:and|shall|must)"
    r"|copyright holders? (?:be liable|and contributors)"
    r"|<year>"
    r"|<copyright holders?>"
    r"|\[year\]"
    r"|\[fullname\]"
    r"|yyyy name of author"
    r"|<name of author>"
    r"|<one line to give"
    r"|NO COPYRIGHT"
    r"|copyright interest"
    r"|copyright (?:law|owner|holder)s? (?:or|of|is|are)"
    r"|means the copyright",
    re.IGNORECASE,
)


def ist_volltext(text: str, mindestlaenge: int = MINDESTLAENGE_VOLLTEXT) -> bool:
    """Sagt, ob ``text`` ein Lizenz-Volltext ist -- nicht nur ein Verweis darauf.

    Verlangt werden Mindestlaenge UND eine echte Lizenzklausel. Eine Datei, die die
    Lizenz nur benennt oder auf sie verweist, gilt nicht als Volltext: sie als
    solchen auszugeben waere ein Ersatztext (Regel 2).
    """
    if len(text) < mindestlaenge:
        return False
    if KLAUSEL_MUSTER.search(text) is None:
        return False
    return not (len(text) <= VERWEIS_HOECHSTLAENGE and VERWEIS_MUSTER.search(text) is not None)


def finde_urhebervermerk(text: str) -> str | None:
    """Liefert die erste Zeile, die ein echter Urhebervermerk ist, sonst ``None``."""
    for rohzeile in text.splitlines():
        zeile = rohzeile.strip()
        if not zeile or len(zeile) > 200:
            continue
        if not COPYRIGHT_MUSTER.match(zeile):
            continue
        if COPYRIGHT_AUSSCHLUSS.search(zeile):
            continue
        return zeile
    return None


def lies_text(pfad: Path) -> str | None:
    """Liest eine Textdatei tolerant; ``None``, wenn sie nicht lesbar ist."""
    try:
        return pfad.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def spdx_teilbezeichner(ausdruck: str | None) -> list[str]:
    """Zerlegt einen SPDX-Ausdruck in die einzelnen Bezeichner.

    ``MIT OR Apache-2.0`` wird zu ``["MIT", "Apache-2.0"]``. Die Zerlegung dient
    allein dazu, die benoetigten Texte der Ablage zu finden -- sie bewertet nicht,
    welche der Alternativen gilt. Diese Wahl ist eine rechtliche Entscheidung und
    wird hier ausdruecklich nicht getroffen.
    """
    if not ausdruck:
        return []
    roh = re.split(r"\(|\)|\bOR\b|\bAND\b|\bWITH\b|/", ausdruck)
    teile: list[str] = []
    for stueck in roh:
        bezeichner = stueck.strip()
        if bezeichner and bezeichner not in teile:
            teile.append(bezeichner)
    return teile


# --------------------------------------------------------------------------------
# Ebene "programme": die aufgerufenen, NICHT mitgelieferten Fremdprogramme
# --------------------------------------------------------------------------------

# Diese Liste stammt aus der Messung S71-L1 Block E (Suchbasis: subprocess.run/Popen/
# call/check_output, asyncio.create_subprocess_exec, shutil.which, os.system ueber
# backend/**/*.py ohne Tests, sowie Command::new / std::process ueber
# src-tauri/src/**/*.rs).
#
# NACHFUEHREN: Aendert sich der Aufrufbestand -- kommt ein Fremdprogramm hinzu, faellt
# eines weg oder wandert eine Fundstelle --, ist diese Liste von Hand nachzuziehen.
# Sie wird nicht aus dem Quelltext erzeugt und veraltet daher stillschweigend.
#
# Kein Eintrag wird mitgeliefert; alle werden vom Betriebssystem oder aus den
# Paketabhaengigkeiten vorausgesetzt. Deshalb fuehrt diese Ebene weder Lizenztext
# noch Urhebervermerk: die Lizenz des jeweiligen Systempakets gehoert zur
# Distribution des Anwenders, nicht zur Auslieferung dieses Produkts.
FREMDPROGRAMME: Final[tuple[dict[str, str], ...]] = (
    {
        "name": "ip",
        "paket": "iproute2",
        "zweck": "Routen, Adressen, MACs, Nachbarn, Default-Route",
        "fundstelle": (
            "backend/infrastructure/interfaces_linux.py:217,218,219; "
            "backend/infrastructure/sniffd/sniff_core.py:206; "
            "backend/modules/discovery.py:130; backend/modules/ipv6.py:87"
        ),
        "plattform": "Linux",
    },
    {
        "name": "ss",
        "paket": "iproute2",
        "zweck": "Durchsatz je Verbindung (TCP-Info)",
        "fundstelle": (
            "backend/infrastructure/traffic_linux.py:314; "
            "backend/infrastructure/traffic_permission.py:44,64"
        ),
        "plattform": "Linux",
    },
    {
        "name": "arp",
        "paket": "net-tools",
        "zweck": "ARP-Tabelle (Alt-Pfad)",
        "fundstelle": "backend/modules/discovery.py:110,121",
        "plattform": "Linux/macOS/Windows",
    },
    {
        "name": "dig",
        "paket": "bind9-dnsutils",
        "zweck": "DNS-Abfragen, PTR-Aufloesung",
        "fundstelle": (
            "backend/infrastructure/diagnostics_linux.py:514,268; "
            "backend/infrastructure/resolver/dns_ptr.py:49,116,148"
        ),
        "plattform": "Linux",
    },
    {
        "name": "traceroute",
        "paket": "traceroute",
        "zweck": "Routenverfolgung",
        "fundstelle": "backend/infrastructure/diagnostics_linux.py:535,549,302,317",
        "plattform": "Linux",
    },
    {
        "name": "nmap",
        "paket": "nmap",
        "zweck": "Portscan, DHCP-Discover-Skript",
        "fundstelle": (
            "backend/infrastructure/diagnostics_linux.py:777,811,821; "
            "backend/modules/portscan.py:120,129,18; backend/app.py:4049"
        ),
        "plattform": "alle",
    },
    {
        "name": "nmblookup",
        "paket": "samba-common-bin",
        "zweck": "NetBIOS-Name/Workgroup",
        "fundstelle": "backend/modules/resolver.py:31",
        "plattform": "Linux",
    },
    {
        "name": "resolvectl",
        "paket": "systemd-resolved",
        "zweck": "systemd-resolved-Status",
        "fundstelle": "backend/infrastructure/system_resolvers.py:159,154",
        "plattform": "Linux",
    },
    {
        "name": "apt, dnf, yum, zypper, pacman",
        "paket": "jeweiliger Paketmanager der Distribution",
        "zweck": "Paketmanager-Erkennung (nur shutil.which, kein Prozessstart)",
        "fundstelle": "backend/infrastructure/diagnostics_linux.py:350,372",
        "plattform": "Linux",
    },
    {
        "name": "netstat",
        "paket": "net-tools (Linux/macOS); Bestandteil von Windows",
        "zweck": "Routentabelle (macOS); Portbelegung (Windows)",
        "fundstelle": ("backend/infrastructure/interfaces_macos.py:212; src-tauri/src/main.rs:166"),
        "plattform": "macOS/Windows",
    },
    {
        "name": "ifconfig",
        "paket": "Bestandteil von macOS",
        "zweck": "Schnittstellen",
        "fundstelle": "backend/infrastructure/interfaces_macos.py:213",
        "plattform": "macOS",
    },
    {
        "name": "ndp",
        "paket": "Bestandteil von macOS",
        "zweck": "IPv6-Nachbarn",
        "fundstelle": "backend/modules/ipv6.py:73",
        "plattform": "macOS",
    },
    {
        "name": "osascript",
        "paket": "Bestandteil von macOS",
        "zweck": "Desktop-Benachrichtigung, Rechte-Dialoge",
        "fundstelle": (
            "backend/infrastructure/alerting/desktop_notifier.py:43; "
            "backend/infrastructure/capture_access_macos.py:340,431; "
            "backend/modules/monitor.py:206"
        ),
        "plattform": "macOS",
    },
    {
        "name": "dscl",
        "paket": "Bestandteil von macOS",
        "zweck": "Gruppenmitgliedschaft (BPF-Zugriff)",
        "fundstelle": "backend/infrastructure/capture_access_macos.py:238",
        "plattform": "macOS",
    },
    {
        "name": "netsh",
        "paket": "Bestandteil von Windows",
        "zweck": "IPv6-Nachbarn",
        "fundstelle": "backend/modules/ipv6.py:81",
        "plattform": "Windows",
    },
    {
        "name": "fuser",
        "paket": "psmisc",
        "zweck": "Port freigeben beim Start",
        "fundstelle": "src-tauri/src/main.rs:157",
        "plattform": "Linux",
    },
    {
        "name": "taskkill",
        "paket": "Bestandteil von Windows",
        "zweck": "Prozessende erzwingen",
        "fundstelle": "src-tauri/src/main.rs:178,709; src-tauri/nsis-hooks.nsi",
        "plattform": "Windows",
    },
    {
        "name": "systemd-detect-virt",
        "paket": "systemd",
        "zweck": "VM-Erkennung",
        "fundstelle": "src-tauri/src/main.rs:397",
        "plattform": "Linux",
    },
    {
        "name": "pkg-config",
        "paket": "pkg-config",
        "zweck": "Bibliotheks-Erkennung zur Laufzeit",
        "fundstelle": "src-tauri/src/main.rs:428",
        "plattform": "Linux",
    },
)


# --------------------------------------------------------------------------------
# Ebene "daten": die mitgelieferten Datenbestaende
# --------------------------------------------------------------------------------

# Auch diese Liste wird im Werkzeug gefuehrt, weil die Bestaende keine eigenen
# Metadaten tragen, aus denen sich Name und Bezeichner ableiten liessen. Der
# Bezeichner stammt jeweils aus der genannten Fundstelle im Repo, nicht aus einer
# eigenen Einschaetzung. Wo keine Fundstelle einen Bezeichner nennt, bleibt er
# ``None`` (Regel 2) -- siehe ``oui.json``.
#
# NACHFUEHREN: kommt ein Datenbestand hinzu oder faellt weg, ist diese Liste
# nachzuziehen.
DATENBESTAENDE: Final[tuple[dict[str, Any], ...]] = (
    {
        "name": "Geo-Zuordnung (asn-country-ipv4/ipv6.csv)",
        "pfad": "backend/data/asn-country-ipv4.csv",
        "lizenz_id": "CC0-1.0",
        # Der Bezeichner steht in der beigelegten Eigendokumentation, nicht in
        # einem Lizenztext: backend/data/asn-country-LICENSE.txt nennt
        # "Lizenz: CC0 1.0", fuehrt aber keinen Wortlaut.
        "lizenz_id_quelle": QUELLE_PAKETDATEI,
        "lizenz_id_fundstelle": "backend/data/asn-country-LICENSE.txt",
        "eigene_lizenzdatei": None,
        "projektadresse": "https://iptoasn.com/",
    },
    {
        "name": "ASN-Zuordnung (iptoasn-asn-ipv4/ipv6.csv)",
        "pfad": "backend/data/iptoasn-asn-ipv4.csv",
        "lizenz_id": "PDDL-1.0",
        "lizenz_id_quelle": QUELLE_PAKETDATEI,
        "lizenz_id_fundstelle": "backend/data/iptoasn-asn-LICENSE.txt",
        "eigene_lizenzdatei": None,
        "projektadresse": "https://iptoasn.com/",
    },
    {
        "name": "OUI-Herstellerliste (oui.json)",
        "pfad": "backend/data/oui.json",
        # Aus der oeffentlichen IEEE-Registerliste erzeugt. Weder die Datei noch
        # das erzeugende Skript nennen einen SPDX-Bezeichner. Nach Regel 2 bleibt
        # das Feld leer, statt eine Einordnung zu erfinden.
        "lizenz_id": None,
        "lizenz_id_quelle": QUELLE_NICHT_BELEGT,
        "lizenz_id_fundstelle": "backend/data/fetch_oui.py",
        "eigene_lizenzdatei": None,
        "projektadresse": "https://standards-oui.ieee.org/",
    },
    {
        "name": "Flaggensymbole (frontend/public/flags)",
        "pfad": "frontend/public/flags",
        "lizenz_id": "MIT",
        "lizenz_id_quelle": QUELLE_PAKETDATEI,
        "lizenz_id_fundstelle": "frontend/public/flags/LICENSE",
        "eigene_lizenzdatei": "frontend/public/flags/LICENSE",
        "projektadresse": "https://github.com/lipis/flag-icons",
    },
    {
        "name": "DoH-Werksliste (doh_builtin)",
        "pfad": "backend/domain/blocklist.py",
        "lizenz_id": "CC0-1.0",
        "lizenz_id_quelle": QUELLE_PAKETDATEI,
        "lizenz_id_fundstelle": "backend/domain/blocklist.py",
        "eigene_lizenzdatei": None,
        "projektadresse": None,
    },
)


# --------------------------------------------------------------------------------
# Sammler
# --------------------------------------------------------------------------------


class Sammler:
    """Traegt die Bestandteile zusammen und verwaltet die Lizenztext-Ablage."""

    def __init__(self, wurzel: Path) -> None:
        self.wurzel = wurzel
        self.ablage = wurzel / "LICENSES"
        self.bestandteile: list[dict[str, Any]] = []
        #: Schluessel -> Eintrag. Jeder Volltext steht genau einmal.
        self.lizenztexte: dict[str, dict[str, Any]] = {}
        #: Pruefsumme -> Schluessel, damit derselbe Text nicht zweimal landet.
        self._nach_pruefsumme: dict[str, str] = {}

    # -- Ablage der Lizenztexte ---------------------------------------------------

    def _eintragen(self, schluessel: str, text: str, quelle: str, herkunft: str) -> str:
        """Legt einen Volltext genau einmal ab und liefert seinen Schluessel."""
        pruefsumme = sha256(text)
        vorhanden = self._nach_pruefsumme.get(pruefsumme)
        if vorhanden is not None:
            return vorhanden
        endgueltig = schluessel
        zaehler = 2
        while endgueltig in self.lizenztexte:
            endgueltig = f"{schluessel}#{zaehler}"
            zaehler += 1
        self.lizenztexte[endgueltig] = {
            "text": text,
            "quelle": quelle,
            "herkunft": herkunft,
            "sha256": pruefsumme,
            "zeichen": len(text),
        }
        self._nach_pruefsumme[pruefsumme] = endgueltig
        return endgueltig

    def text_aus_paketdatei(self, bestandteil: str, datei: Path, text: str) -> tuple[str, str]:
        """REGEL 1, erster Rang: der Text, den das Paket selbst mitbringt."""
        try:
            herkunft = str(datei.relative_to(self.wurzel))
        except ValueError:
            herkunft = str(datei)
        schluessel = self._eintragen(f"paket:{bestandteil}", text, QUELLE_PAKETDATEI, herkunft)
        return schluessel, QUELLE_PAKETDATEI

    def text_aus_ablage(self, bezeichner: str) -> tuple[str, str] | None:
        """REGEL 1, zweiter Rang: die abgelegte SPDX-Fassung.

        Fuer ``GPL-2.0-only`` liefert diese Stelle nie einen SPDX-Text -- dort gilt
        die Wurzel-LICENSE, siehe :meth:`text_aus_werk_lizenz`.
        """
        if bezeichner == GPL2_ONLY:
            return self.text_aus_werk_lizenz()
        datei = self.ablage / f"{bezeichner}.txt"
        text = lies_text(datei) if datei.is_file() else None
        if text is None:
            return None
        schluessel = self._eintragen(
            f"spdx:{bezeichner}",
            text,
            QUELLE_SPDX_ABLAGE,
            f"LICENSES/{bezeichner}.txt",
        )
        return schluessel, QUELLE_SPDX_ABLAGE

    def text_aus_werk_lizenz(self) -> tuple[str, str] | None:
        """REGEL 1, Sonderfall GPL-2.0-only: die Wurzel-LICENSE des Projekts.

        Die SPDX-Fassung von GPL-2.0-only ist gemessen unvollstaendig -- ihr fehlen
        die wiederholte Ueberschrift und der Schlussabsatz. Deshalb wird hier nie
        auf die Ablage zurueckgegriffen.
        """
        datei = self.wurzel / "LICENSE"
        text = lies_text(datei) if datei.is_file() else None
        if text is None:
            return None
        schluessel = self._eintragen(f"werk:{GPL2_ONLY}", text, QUELLE_WERK_LIZENZ, "LICENSE")
        return schluessel, QUELLE_WERK_LIZENZ

    def loese_text(
        self,
        bestandteil: str,
        bezeichner: str | None,
        paketdatei: tuple[Path, str] | None,
    ) -> tuple[str | None, str]:
        """Waehlt den Lizenztext nach Regel 1 und meldet die gewaehlte Quelle.

        Rangfolge: eigene Paketdatei -> Ablage bzw. Wurzel-LICENSE -> nicht belegt.
        Es wird nie ein fremder oder generischer Text eingesetzt (Regel 2).
        """
        if paketdatei is not None:
            datei, text = paketdatei
            return self.text_aus_paketdatei(bestandteil, datei, text)
        for teil in spdx_teilbezeichner(bezeichner):
            treffer = self.text_aus_ablage(teil)
            if treffer is not None:
                return treffer
        return None, QUELLE_NICHT_BELEGT

    # -- Eintraege ----------------------------------------------------------------

    def anfuegen(
        self,
        *,
        name: str,
        fassung: str | None,
        ebene: str,
        lizenz_id: str | None,
        lizenz_id_quelle: str,
        urhebervermerk: str | None,
        urhebervermerk_quelle: str,
        lizenz_text_ref: str | None,
        projektadresse: str | None,
        mitgeliefert: bool,
        **zusatz: Any,
    ) -> None:
        eintrag: dict[str, Any] = {
            "name": name,
            "fassung": fassung,
            "ebene": ebene,
            "lizenz_id": lizenz_id,
            "lizenz_id_quelle": lizenz_id_quelle,
            "urhebervermerk": urhebervermerk,
            "urhebervermerk_quelle": urhebervermerk_quelle,
            "lizenz_text_ref": lizenz_text_ref,
            "projektadresse": projektadresse,
            "mitgeliefert": mitgeliefert,
        }
        eintrag.update(zusatz)
        for feld in ("lizenz_id_quelle", "urhebervermerk_quelle"):
            if eintrag[feld] not in ZULAESSIGE_QUELLEN:
                raise ValueError(f"{name}: unzulaessige Quelle {eintrag[feld]!r}")
        self.bestandteile.append(eintrag)


# --------------------------------------------------------------------------------
# Ebene python
# --------------------------------------------------------------------------------


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _classifier_bezeichner(classifier: Sequence[str]) -> str | None:
    """Uebersetzt die gaengigen Trove-Classifier in ihren SPDX-Bezeichner.

    Die Zuordnung ist eine reine Namensuebersetzung zwischen zwei Registern, keine
    rechtliche Wertung. Was hier nicht steht, bleibt unbelegt (Regel 2).
    """
    tabelle = {
        "License :: OSI Approved :: MIT License": "MIT",
        "License :: OSI Approved :: BSD License": "BSD-3-Clause",
        "License :: OSI Approved :: Apache Software License": "Apache-2.0",
        "License :: OSI Approved :: ISC License (ISCL)": "ISC",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": GPL2_ONLY,
        "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    }
    for eintrag in classifier:
        treffer = tabelle.get(eintrag.strip())
        if treffer is not None:
            return treffer
    return None


def _lizenzdateien(verzeichnis: Path) -> list[Path]:
    """Alle Dateien eines Verzeichnisses, die eine Lizenzdatei sein koennen."""
    if not verzeichnis.is_dir():
        return []
    treffer: list[Path] = []
    for pfad in sorted(verzeichnis.iterdir()):
        if not pfad.is_file():
            continue
        if pfad.suffix.lower() in KEIN_LIZENZTEXT_ENDUNG:
            continue
        if LIZENZDATEI_MUSTER.match(pfad.name):
            treffer.append(pfad)
    return treffer


def _dateiname_passt(name: str, bezeichner: str) -> bool:
    """Sagt, ob ein Dateiname den Bezeichner nennt (``LICENSE-MIT`` zu ``MIT``).

    Verglichen wird wortweise, nicht als Zeichenkette: der Bezeichner kann als
    ``MIT License`` geschrieben sein, die Datei als ``LICENSE-MIT``. Das Wort
    ``LICENSE`` selbst traegt dabei nichts zur Unterscheidung bei und wird
    uebergangen -- sonst passte jede Lizenzdatei auf jeden Bezeichner.
    """
    fuellwoerter = {"LICENSE", "LICENCE", "COPYING", "TXT", "MD", "0"}
    worte_datei = {w for w in re.split(r"[^A-Z0-9]+", name.upper()) if w}
    worte_id = {
        w for w in re.split(r"[^A-Z0-9]+", bezeichner.upper()) if w and w not in fuellwoerter
    }
    if not worte_id:
        return False
    return bool(worte_id & (worte_datei - fuellwoerter))


def _beste_paketdatei(
    kandidaten: Iterable[Path],
    mindestlaenge: int,
    bezeichner: str | None = None,
) -> tuple[Path, str] | None:
    """Waehlt unter den Lizenzdateien eines Pakets die mit echtem Volltext.

    Fuehrt ein Paket mehrere Lizenzdateien (etwa ``LICENSE-MIT`` neben
    ``LICENSE-APACHE``), erhaelt die den Vorzug, deren Name den angegebenen
    Bezeichner nennt. Sonst wuerde bei einem Paket mit Doppellizenz der Text der
    jeweils anderen Lizenz ausgegeben.

    Eine Datei, die zwar so heisst, aber keinen Volltext fuehrt (etwa ein blosser
    Verweis auf eine Adresse), wird NICHT als Lizenztext ausgegeben -- das waere ein
    Ersatztext im Sinne von Regel 2. Den Urhebervermerk darf sie dennoch liefern;
    das entscheidet der Aufrufer ueber :func:`_urhebervermerk_aus_dateien`.
    """
    treffer: list[tuple[Path, str]] = []
    for pfad in kandidaten:
        text = lies_text(pfad)
        if text is None:
            continue
        if ist_volltext(text, mindestlaenge):
            treffer.append((pfad, text))
    if not treffer:
        return None
    for teil in spdx_teilbezeichner(bezeichner):
        for pfad, text in treffer:
            if _dateiname_passt(pfad.name, teil):
                return pfad, text
    return treffer[0]


def _urhebervermerk_aus_dateien(kandidaten: Iterable[Path]) -> tuple[str, Path] | None:
    for pfad in kandidaten:
        text = lies_text(pfad)
        if text is None:
            continue
        vermerk = finde_urhebervermerk(text)
        if vermerk is not None:
            return vermerk, pfad
    return None


def sammle_python(sammler: Sammler, wurzel: Path) -> None:
    """Produktive Huelle aus den dist-info-Metadaten der Installation.

    Feldrang fuer den Bezeichner: ``License-Expression`` vor ``License`` vor
    ``Classifier``. Ein blosser Classifier ist die schwaechere Quelle und wird als
    solche gekennzeichnet.
    """
    ausgabe = subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--no-hashes",
        ],
        cwd=wurzel,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    gelockt: dict[str, str] = {}
    for zeile in ausgabe.splitlines():
        treffer = re.match(r"^([A-Za-z0-9._-]+)==([^\s;]+)", zeile.strip())
        if treffer:
            gelockt[_pep503(treffer.group(1))] = treffer.group(2)

    sitepackages = wurzel / ".venv" / "lib" / "python3.12" / "site-packages"
    gefunden: set[str] = set()
    for distinfo in sorted(sitepackages.glob("*.dist-info")):
        metadaten = distinfo / "METADATA"
        if not metadaten.is_file():
            continue
        roh = lies_text(metadaten)
        if roh is None:
            continue
        kopf = email.message_from_string(roh)
        name = kopf.get("Name") or ""
        schluessel = _pep503(name)
        if schluessel not in gelockt:
            continue
        gefunden.add(schluessel)

        # Feldrang des Bezeichners.
        ausdruck = kopf.get("License-Expression")
        feld_license = (kopf.get("License") or "").strip()
        classifier = [c for c in (kopf.get_all("Classifier") or []) if c.startswith("License ::")]
        nur_classifier = False
        if ausdruck:
            bezeichner: str | None = ausdruck.strip()
            bezeichner_quelle = QUELLE_PAKETMETADATEN
        elif feld_license and "\n" not in feld_license and len(feld_license) <= 40:
            bezeichner = feld_license
            bezeichner_quelle = QUELLE_PAKETMETADATEN
        else:
            bezeichner = _classifier_bezeichner(classifier)
            bezeichner_quelle = QUELLE_PAKETMETADATEN if bezeichner else QUELLE_NICHT_BELEGT
            nur_classifier = bezeichner is not None

        # Lizenzdateien des Pakets: dist-info/licenses/ und dist-info/ selbst.
        kandidaten = _lizenzdateien(distinfo / "licenses") + _lizenzdateien(distinfo)
        paketdatei = _beste_paketdatei(kandidaten, MINDESTLAENGE_VOLLTEXT, bezeichner)
        ref, textquelle = sammler.loese_text(f"python/{name}", bezeichner, paketdatei)

        vermerk_treffer = _urhebervermerk_aus_dateien(kandidaten)
        if vermerk_treffer is not None:
            vermerk: str | None = vermerk_treffer[0]
            vermerk_quelle = QUELLE_PAKETDATEI
        else:
            vermerk = None
            vermerk_quelle = QUELLE_NICHT_BELEGT

        sammler.anfuegen(
            name=name,
            fassung=kopf.get("Version"),
            ebene="python",
            lizenz_id=bezeichner,
            lizenz_id_quelle=bezeichner_quelle,
            urhebervermerk=vermerk,
            urhebervermerk_quelle=vermerk_quelle,
            lizenz_text_ref=ref,
            projektadresse=kopf.get("Home-page") or _projektadresse_aus_urls(kopf),
            mitgeliefert=True,
            lizenz_text_quelle=textquelle,
            lizenz_id_nur_classifier=nur_classifier,
        )

    # Gelockte, aber auf dieser Plattform nicht installierte Pakete werden nicht
    # mitgeliefert und daher nicht als Bestandteil gefuehrt. Sie erscheinen im
    # Bericht als Differenz zwischen 51 gelockten und den installierten Paketen.
    _ = gefunden


def _projektadresse_aus_urls(kopf: email.message.Message) -> str | None:
    for eintrag in kopf.get_all("Project-URL") or []:
        beschriftung, _, adresse = eintrag.partition(",")
        if beschriftung.strip().lower() in {"homepage", "source", "repository"}:
            return adresse.strip() or None
    return None


# --------------------------------------------------------------------------------
# Ebene npm
# --------------------------------------------------------------------------------


def _npm_baum(verzeichnis: Path) -> dict[str, Any]:
    ergebnis = subprocess.run(
        ["npm", "ls", "--omit=dev", "--all", "--json"],
        cwd=verzeichnis,
        capture_output=True,
        text=True,
        check=False,
    )
    # npm meldet bei fehlenden optionalen Peers einen Fehlercode, liefert den Baum
    # aber trotzdem. Nur ein unlesbarer Baum ist ein echter Fehler.
    return json.loads(ergebnis.stdout) if ergebnis.stdout.strip() else {}


def _npm_flach(baum: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Klopft den npm-Abhaengigkeitsbaum zu einer flachen Zuordnung auseinander.

    Eintraege ohne aufgeloeste Fassung sind unerfuellte optionale Peers -- sie sind
    nicht installiert und werden nicht ausgeliefert, gehoeren also nicht in die
    Aufstellung.
    """
    flach: dict[tuple[str, str], dict[str, Any]] = {}
    stapel: list[dict[str, Any]] = [baum]
    while stapel:
        knoten = stapel.pop()
        for name, info in (knoten.get("dependencies") or {}).items():
            fassung = info.get("version")
            if fassung:
                flach[(name, fassung)] = info
            stapel.append(info)
    return flach


def sammle_npm(sammler: Sammler, wurzel: Path) -> None:
    """Produktive Huelle des Frontends plus die Wurzelabhaengigkeit."""
    orte = [("frontend", wurzel / "frontend"), ("wurzel", wurzel)]
    gesehen: set[tuple[str, str]] = set()
    for herkunft, verzeichnis in orte:
        flach = _npm_flach(_npm_baum(verzeichnis))
        for (name, fassung), info in sorted(flach.items()):
            if (name, fassung) in gesehen:
                continue
            gesehen.add((name, fassung))
            pfad_roh = info.get("path")
            paketverzeichnis = (
                Path(pfad_roh)
                if pfad_roh
                else verzeichnis / "node_modules" / Path(*name.split("/"))
            )
            paketjson = paketverzeichnis / "package.json"
            angaben: dict[str, Any] = {}
            roh = lies_text(paketjson)
            if roh:
                try:
                    angaben = json.loads(roh)
                except json.JSONDecodeError:
                    angaben = {}

            lizenzfeld = angaben.get("license")
            if isinstance(lizenzfeld, dict):
                lizenzfeld = lizenzfeld.get("type")
            if isinstance(lizenzfeld, str) and lizenzfeld.strip():
                bezeichner: str | None = lizenzfeld.strip()
                bezeichner_quelle = QUELLE_PAKETMETADATEN
            else:
                bezeichner = None
                bezeichner_quelle = QUELLE_NICHT_BELEGT

            kandidaten = _lizenzdateien(paketverzeichnis)
            paketdatei = _beste_paketdatei(kandidaten, MINDESTLAENGE_VOLLTEXT, bezeichner)
            ref, textquelle = sammler.loese_text(f"npm/{name}", bezeichner, paketdatei)

            vermerk_treffer = _urhebervermerk_aus_dateien(kandidaten)
            if vermerk_treffer is not None:
                vermerk: str | None = vermerk_treffer[0]
                vermerk_quelle = QUELLE_PAKETDATEI
            else:
                # Die SPDX-Metadatensaetze (LICENSE.spdx) fuehren einen echten
                # Urhebervermerk, aber keinen Lizenztext. Sie sind daher als Quelle
                # des Vermerks zulaessig -- nicht als Quelle des Textes.
                vermerk, vermerk_quelle = _npm_vermerk_aus_spdx_satz(paketverzeichnis)

            sammler.anfuegen(
                name=name,
                fassung=fassung,
                ebene="npm",
                lizenz_id=bezeichner,
                lizenz_id_quelle=bezeichner_quelle,
                urhebervermerk=vermerk,
                urhebervermerk_quelle=vermerk_quelle,
                lizenz_text_ref=ref,
                projektadresse=_npm_adresse(angaben),
                mitgeliefert=True,
                lizenz_text_quelle=textquelle,
                npm_ort=herkunft,
            )


def _npm_vermerk_aus_spdx_satz(paketverzeichnis: Path) -> tuple[str | None, str]:
    satz = paketverzeichnis / "LICENSE.spdx"
    text = lies_text(satz) if satz.is_file() else None
    if text is None:
        return None, QUELLE_NICHT_BELEGT
    for zeile in text.splitlines():
        if zeile.startswith("PackageCopyrightText:"):
            wert = zeile.split(":", 1)[1].strip()
            if wert and wert.upper() not in {"NOASSERTION", "NONE"}:
                return wert, QUELLE_PAKETDATEI
    return None, QUELLE_NICHT_BELEGT


def _npm_adresse(angaben: dict[str, Any]) -> str | None:
    ablage = angaben.get("repository")
    if isinstance(ablage, dict):
        ablage = ablage.get("url")
    if isinstance(ablage, str) and ablage.strip():
        return ablage.strip()
    heim = angaben.get("homepage")
    return heim.strip() if isinstance(heim, str) and heim.strip() else None


# --------------------------------------------------------------------------------
# Ebene rust
# --------------------------------------------------------------------------------


def sammle_rust(sammler: Sammler, wurzel: Path) -> None:
    """Die Crates des Linux-x64-Ziels, Lizenztext aus dem Registry-Cache."""
    manifest = wurzel / "src-tauri" / "Cargo.toml"
    metadaten = json.loads(
        subprocess.run(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--manifest-path",
                str(manifest),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    baum = subprocess.run(
        [
            "cargo",
            "tree",
            "--locked",
            "--manifest-path",
            str(manifest),
            "--target",
            RUST_ZIEL,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--no-dedupe",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    eigenes = {(p["name"], p["version"]) for p in metadaten["packages"] if p.get("source") is None}
    im_ziel: set[tuple[str, str]] = set()
    for zeile in baum.splitlines():
        treffer = re.match(r"^([A-Za-z0-9_.+-]+) v([^\s]+)", zeile.strip())
        if treffer:
            im_ziel.add((treffer.group(1), treffer.group(2)))
    im_ziel -= eigenes

    nach_kennung = {(p["name"], p["version"]): p for p in metadaten["packages"]}
    for kennung in sorted(im_ziel):
        paket = nach_kennung.get(kennung)
        if paket is None:
            continue
        name, fassung = kennung
        ausdruck = paket.get("license")
        if ausdruck:
            bezeichner: str | None = ausdruck.strip()
            bezeichner_quelle = QUELLE_PAKETMETADATEN
        elif paket.get("license_file"):
            bezeichner = None
            bezeichner_quelle = QUELLE_NICHT_BELEGT
        else:
            bezeichner = None
            bezeichner_quelle = QUELLE_NICHT_BELEGT

        quellverzeichnis = (
            Path(paket["manifest_path"]).parent if paket.get("manifest_path") else None
        )
        kandidaten = _lizenzdateien(quellverzeichnis) if quellverzeichnis is not None else []
        paketdatei = _beste_paketdatei(kandidaten, MINDESTLAENGE_VOLLTEXT_RUST, bezeichner)
        ref, textquelle = sammler.loese_text(f"rust/{name}", bezeichner, paketdatei)

        vermerk_treffer = _urhebervermerk_aus_dateien(kandidaten)
        if vermerk_treffer is not None:
            vermerk: str | None = vermerk_treffer[0]
            vermerk_quelle = QUELLE_PAKETDATEI
        else:
            # Zweitquelle: der Autorenvermerk im Crate-Manifest. Er ist eine
            # Angabe des Pakets ueber sich selbst, also Paketmetadaten.
            autoren = [a for a in (paket.get("authors") or []) if a.strip()]
            if autoren:
                vermerk = ", ".join(autoren)
                vermerk_quelle = QUELLE_PAKETMETADATEN
            else:
                vermerk = None
                vermerk_quelle = QUELLE_NICHT_BELEGT

        sammler.anfuegen(
            name=name,
            fassung=fassung,
            ebene="rust",
            lizenz_id=bezeichner,
            lizenz_id_quelle=bezeichner_quelle,
            urhebervermerk=vermerk,
            urhebervermerk_quelle=vermerk_quelle,
            lizenz_text_ref=ref,
            projektadresse=paket.get("repository") or paket.get("homepage"),
            mitgeliefert=True,
            lizenz_text_quelle=textquelle,
        )


# --------------------------------------------------------------------------------
# Ebenen daten und programme
# --------------------------------------------------------------------------------


def sammle_daten(sammler: Sammler, wurzel: Path) -> None:
    """Die Bestaende unter backend/data und frontend/public/flags."""
    for bestand in DATENBESTAENDE:
        eigene = bestand.get("eigene_lizenzdatei")
        paketdatei: tuple[Path, str] | None = None
        kandidaten: list[Path] = []
        if eigene:
            pfad = wurzel / str(eigene)
            text = lies_text(pfad) if pfad.is_file() else None
            if text is not None:
                kandidaten.append(pfad)
                if ist_volltext(text):
                    paketdatei = (pfad, text)

        ref, textquelle = sammler.loese_text(
            f"daten/{bestand['name']}", bestand["lizenz_id"], paketdatei
        )
        vermerk_treffer = _urhebervermerk_aus_dateien(kandidaten)
        if vermerk_treffer is not None:
            vermerk: str | None = vermerk_treffer[0]
            vermerk_quelle = QUELLE_PAKETDATEI
        else:
            vermerk = None
            vermerk_quelle = QUELLE_NICHT_BELEGT

        sammler.anfuegen(
            name=str(bestand["name"]),
            fassung=None,
            ebene="daten",
            lizenz_id=bestand["lizenz_id"],
            lizenz_id_quelle=str(bestand["lizenz_id_quelle"]),
            urhebervermerk=vermerk,
            urhebervermerk_quelle=vermerk_quelle,
            lizenz_text_ref=ref,
            projektadresse=bestand.get("projektadresse"),
            mitgeliefert=True,
            lizenz_text_quelle=textquelle,
            pfad=str(bestand["pfad"]),
            lizenz_id_fundstelle=bestand.get("lizenz_id_fundstelle"),
        )


def sammle_programme(sammler: Sammler) -> None:
    """Die aufgerufenen, NICHT mitgelieferten Fremdprogramme (S71-L1 Block E)."""
    for programm in FREMDPROGRAMME:
        # Diese Programme werden nicht ausgeliefert. Ihre Lizenz gehoert zum
        # Systempaket der jeweiligen Distribution, nicht zu dieser Auslieferung --
        # deshalb bleiben Bezeichner, Text und Vermerk unbelegt (Regel 2).
        sammler.anfuegen(
            name=programm["name"],
            fassung=None,
            ebene="programme",
            lizenz_id=None,
            lizenz_id_quelle=QUELLE_NICHT_BELEGT,
            urhebervermerk=None,
            urhebervermerk_quelle=QUELLE_NICHT_BELEGT,
            lizenz_text_ref=None,
            projektadresse=None,
            mitgeliefert=False,
            lizenz_text_quelle=QUELLE_NICHT_BELEGT,
            quelle_der_angabe=QUELLE_WERKZEUG_LISTE,
            lieferndes_paket=programm["paket"],
            zweck=programm["zweck"],
            fundstelle=programm["fundstelle"],
            plattform=programm["plattform"],
        )


# --------------------------------------------------------------------------------
# Werk und Zusammenbau
# --------------------------------------------------------------------------------


def lies_produktversion(wurzel: Path) -> str:
    with (wurzel / "pyproject.toml").open("rb") as strom:
        daten = tomllib.load(strom)
    version = daten.get("project", {}).get("version")
    if not isinstance(version, str):
        raise SystemExit("pyproject.toml fuehrt keine Version unter project.version")
    return version


def baue_werk(sammler: Sammler, wurzel: Path) -> dict[str, Any]:
    """Das eigene Werk. Der Lizenztext ist die Wurzel-LICENSE, nie die SPDX-Fassung."""
    with (wurzel / "pyproject.toml").open("rb") as strom:
        daten = tomllib.load(strom)
    projekt = daten.get("project", {})
    bezeichner = projekt.get("license")
    if isinstance(bezeichner, dict):
        bezeichner = bezeichner.get("text")
    autoren = [
        str(a["name"]) for a in projekt.get("authors", []) if isinstance(a, dict) and a.get("name")
    ]
    treffer = sammler.text_aus_werk_lizenz()
    if treffer is None:
        ref, quelle = None, QUELLE_NICHT_BELEGT
    else:
        ref, quelle = treffer

    # Der Urhebervermerk des Werks stammt aus den eigenen Projektdateien, NICHT aus
    # der Wurzel-LICENSE: die fuehrt den Vermerk der Free Software Foundation ueber
    # den Lizenztext selbst, nicht den des Werks. Ihn hier zu uebernehmen waere eine
    # falsche Zuschreibung (Regel 2).
    if autoren:
        urheber: str | None = ", ".join(autoren)
    else:
        urheber = _werk_urheber_aus_tauri(wurzel)
    return {
        "name": projekt.get("name"),
        "urheber": urheber,
        "lizenz_id": bezeichner,
        "lizenz_text": ref,
        "lizenz_text_quelle": quelle,
    }


def _werk_urheber_aus_tauri(wurzel: Path) -> str | None:
    """Liest den Urhebervermerk des Werks aus ``src-tauri/tauri.conf.json``."""
    roh = lies_text(wurzel / "src-tauri" / "tauri.conf.json")
    if roh is None:
        return None
    try:
        angaben = json.loads(roh)
    except json.JSONDecodeError:
        return None
    vermerk = angaben.get("bundle", {}).get("copyright")
    return vermerk.strip() if isinstance(vermerk, str) and vermerk.strip() else None


def sammle_luecken(bestandteile: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Alle Bestandteile mit fehlendem Text oder fehlendem Urhebervermerk."""
    luecken: list[dict[str, Any]] = []
    for eintrag in bestandteile:
        fehlt: list[str] = []
        if eintrag["lizenz_text_ref"] is None:
            fehlt.append("lizenz_text")
        if eintrag["urhebervermerk"] is None:
            fehlt.append("urhebervermerk")
        if not fehlt:
            continue
        luecken.append(
            {
                "name": eintrag["name"],
                "fassung": eintrag["fassung"],
                "ebene": eintrag["ebene"],
                "lizenz_id": eintrag["lizenz_id"],
                "fehlt": fehlt,
            }
        )
    return luecken


def pruefe_ergebnis(ergebnis: dict[str, Any]) -> None:
    """Prueft die Zusagen des Datenformats, bevor geschrieben wird.

    Ein Verstoss ist ein Fehler, kein stiller Rueckfall: das Werkzeug bricht ab.
    """
    texte = ergebnis["lizenztexte"]
    pruefsummen = [eintrag["sha256"] for eintrag in texte.values()]
    if len(set(pruefsummen)) != len(pruefsummen):
        raise SystemExit("Ein Lizenztext steht mehrfach in lizenztexte")
    verweise = [
        eintrag["lizenz_text_ref"]
        for eintrag in ergebnis["bestandteile"]
        if eintrag["lizenz_text_ref"] is not None
    ]
    werkverweis = ergebnis["werk"]["lizenz_text"]
    if werkverweis is not None:
        verweise.append(werkverweis)
    unbekannt = sorted({v for v in verweise if v not in texte})
    if unbekannt:
        raise SystemExit(f"lizenz_text_ref ohne Eintrag in lizenztexte: {unbekannt}")
    for eintrag in ergebnis["bestandteile"]:
        for feld in ("lizenz_id", "urhebervermerk"):
            quelle = eintrag[f"{feld}_quelle"]
            if eintrag[feld] is None and quelle != QUELLE_NICHT_BELEGT:
                raise SystemExit(f"{eintrag['name']}: {feld} ist leer, Quelle aber {quelle!r}")
            if eintrag[feld] == "":
                raise SystemExit(f"{eintrag['name']}: {feld} ist ein leerer String")


def erzeuge(wurzel: Path) -> dict[str, Any]:
    sammler = Sammler(wurzel)
    sammle_python(sammler, wurzel)
    sammle_npm(sammler, wurzel)
    sammle_rust(sammler, wurzel)
    sammle_daten(sammler, wurzel)
    sammle_programme(sammler)

    ergebnis: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "erzeugt_am": datetime.now(UTC).isoformat(timespec="seconds"),
        "produktversion": lies_produktversion(wurzel),
        "plattform": PLATTFORM,
        "werk": baue_werk(sammler, wurzel),
        "bestandteile": sammler.bestandteile,
        "lizenztexte": sammler.lizenztexte,
        "luecken": sammle_luecken(sammler.bestandteile),
        "ebene_nativ": {
            "erhoben": False,
            "hinweis": EBENE_NATIV_HINWEIS,
            "eintraege": [],
        },
    }
    pruefe_ergebnis(ergebnis)
    return ergebnis


def main(argv: Sequence[str] | None = None) -> int:
    zerleger = argparse.ArgumentParser(
        description=(
            "Erzeugt die Aufstellung aller mitgelieferten Fremdbestandteile "
            "mit Lizenzbezeichner, Lizenztext, Urhebervermerk und Herkunft."
        )
    )
    zerleger.add_argument("ausgabe", type=Path, help="Pfad der zu schreibenden JSON-Datei")
    zerleger.add_argument(
        "--wurzel",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repo-Wurzelverzeichnis (Vorgabe: das Verzeichnis ueber scripts/)",
    )
    argumente = zerleger.parse_args(argv)

    wurzel = argumente.wurzel.resolve()
    ergebnis = erzeuge(wurzel)
    argumente.ausgabe.parent.mkdir(parents=True, exist_ok=True)
    argumente.ausgabe.write_text(
        json.dumps(ergebnis, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    je_ebene: dict[str, int] = {}
    for eintrag in ergebnis["bestandteile"]:
        je_ebene[eintrag["ebene"]] = je_ebene.get(eintrag["ebene"], 0) + 1
    luecken = ergebnis["luecken"]
    ohne_text = sum(1 for luecke in luecken if "lizenz_text" in luecke["fehlt"])
    ohne_vermerk = sum(1 for luecke in luecken if "urhebervermerk" in luecke["fehlt"])

    print(f"geschrieben: {argumente.ausgabe}")
    for ebene in sorted(je_ebene):
        print(f"  Ebene {ebene:<10} {je_ebene[ebene]:>4} Eintraege")
    print(f"  Bestandteile gesamt      {len(ergebnis['bestandteile']):>4}")
    print(f"  Lizenztexte abgelegt     {len(ergebnis['lizenztexte']):>4}")
    print(f"  Luecken ohne Lizenztext  {ohne_text:>4}")
    print(f"  Luecken ohne Vermerk     {ohne_vermerk:>4}")
    print("  Ebene nativ: in diesem Schritt nicht erhoben (P3b)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
