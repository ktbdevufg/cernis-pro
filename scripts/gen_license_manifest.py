#!/usr/bin/env python3
"""Erzeugt die maschinenlesbare Aufstellung aller mitgelieferten Fremdbestandteile.

Aufruf::

    python scripts/gen_license_manifest.py <ausgabepfad.json>
    python scripts/gen_license_manifest.py <ausgabepfad.json> --binaerverzeichnis <verz>
    python scripts/gen_license_manifest.py <ausgabepfad.json> --zielplattform windows-x86_64

Das Werkzeug ist eigenstaendig: es importiert nichts aus ``backend`` und kommt mit
der Standardbibliothek aus. Es sammelt die Ebenen ``python``, ``npm``, ``rust``,
``daten`` und ``programme`` und schreibt EINE JSON-Datei.

Die Ebene ``nativ`` wird nur erhoben, wenn ``--binaerverzeichnis`` auf ein
Verzeichnis mit den fertigen PyInstaller-Binaries zeigt. Der Grund fuer den
Schalter: welche nativen Bibliotheken mitgeliefert werden, steht erst NACH dem
PyInstaller-Lauf fest, denn sie stammen aus dessen Abhaengigkeitsanalyse.

Diese Ebene kennt DREI Zustaende, im Feld ``zustand`` unterschieden, damit eine
Anzeige sie nicht aus leeren Listen erraten muss:

``nicht_angefordert``
    Es wurde kein ``--binaerverzeichnis`` uebergeben.
``erhoben``
    Bibliotheken gefunden und ein Paketverzeichnis vorhanden.
``kein_paketverzeichnis``
    Angefordert, aber auf der Zielplattform nicht ermittelbar: dort gibt es keine
    Datei-zu-Paket-Zuordnung, aus der sich Systempaket und Lizenztext belegen
    liessen. Das ist der Windows- und macOS-Fall, kein Fehler und kein Abbruch.

Die ZIELplattform kommt aus ``--zielplattform`` und wird nie aus der laufenden
Maschine geraten. Aus ihr folgen das Rust-Ziel (``cargo tree --target``) und die
Endungen der nativen Bibliotheken. Ohne den Schalter gilt ``linux-x86_64``: ein
Aufruf ohne ihn verhaelt sich damit genau wie bisher.

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

    Auf der Ebene ``nativ`` gilt die Regel unveraendert: findet sich zu einer
    Bibliothek kein Paket oder zum Paket keine ``copyright``-Datei, bleibt der
    Eintrag ``nicht_belegt``. Es wird nichts genaehert -- weder ueber eine andere
    Distribution noch ueber eine gleichnamige Bibliothek anderer Herkunft.

Das Werkzeug faellt kein rechtliches Urteil. Es benennt zu jeder Angabe ihre
Herkunft und kennzeichnet, was nicht belegt ist.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import sysconfig
import tomllib
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Final

# --------------------------------------------------------------------------------
# Feste Werte des Datenformats
# --------------------------------------------------------------------------------

#: Die Fassung des Datenformats. Sie wird angehoben, sobald eine Anzeige die Datei
#: nicht mehr wie zuvor lesen kann.
#:
#: "1" -> "2": Mit der Zielplattform-Erweiterung hat sich der VERTRAG geaendert,
#: nicht nur der Inhalt. ``ebene_nativ`` fuehrt das neue Pflichtfeld ``zustand`` mit
#: drei Werten, und ``erhoben=false`` ist damit nicht mehr eindeutig -- es steht nun
#: fuer zwei verschiedene Sachverhalte (nicht angefordert / auf der Zielplattform
#: nicht ermittelbar), die eine Anzeige unterscheiden muss. Dazu kommen
#: ``zielplattform``, ``quelle_der_binaries`` und ``gelesene_binaries`` in allen drei
#: Zustaenden. Vor allem aber hat ``plattform`` seine Bedeutung gewechselt: es nennt
#: nicht mehr die feste Konstante ``linux-x86_64``, sondern die uebergebene
#: ZIELplattform. Ein Leser, der den alten Wert als gegeben annahm, liest jetzt
#: still etwas anderes. Das ist keine Ergaenzung, sondern eine Bedeutungsaenderung
#: an einem bestehenden Feld -- deshalb die volle Nummer und keine Unterfassung.
SCHEMA_VERSION: Final = "2"

#: Die einzigen zulaessigen Werte der drei Quellenfelder.
QUELLE_PAKETDATEI: Final = "paketdatei"
QUELLE_PAKETMETADATEN: Final = "paketmetadaten"
QUELLE_SPDX_ABLAGE: Final = "spdx_ablage"
QUELLE_WERK_LIZENZ: Final = "werk_lizenz"
QUELLE_REGISTERLISTE: Final = "registerliste"
QUELLE_WERKZEUG_LISTE: Final = "werkzeug_liste"
#: Die Angabe stammt aus der Paketdatenbank des Systems (Ebene ``nativ``): der
#: Paketname aus der Datei-zu-Paket-Zuordnung, Bezeichner und Urhebervermerk aus
#: den ausgewiesenen Feldern ``License:`` und ``Copyright:`` der
#: ``copyright``-Datei im maschinenlesbaren Format. Der Lizenz-VOLLTEXT traegt
#: dagegen ``paketdatei``: er ist der Wortlaut jener Datei selbst.
QUELLE_SYSTEMPAKET: Final = "systempaket"
#: Die Angabe stammt aus der Projektkonfiguration des EIGENEN Werks, also aus
#: ``pyproject.toml``. Betrifft ausschliesslich den werk-Eintrag; Bestandteile
#: tragen diese Quelle nie.
QUELLE_PROJEKTKONFIGURATION: Final = "projektkonfiguration"
QUELLE_NICHT_BELEGT: Final = "nicht_belegt"

ZULAESSIGE_QUELLEN: Final = frozenset(
    {
        QUELLE_PAKETDATEI,
        QUELLE_PAKETMETADATEN,
        QUELLE_SPDX_ABLAGE,
        QUELLE_WERK_LIZENZ,
        QUELLE_REGISTERLISTE,
        QUELLE_WERKZEUG_LISTE,
        QUELLE_SYSTEMPAKET,
        QUELLE_PROJEKTKONFIGURATION,
        QUELLE_NICHT_BELEGT,
    }
)

#: Der Bezeichner, fuer den die SPDX-Fassung nie verwendet wird (Regel 1).
GPL2_ONLY: Final = "GPL-2.0-only"

EBENE_NATIV_HINWEIS: Final = (
    "Ohne --binaerverzeichnis nicht erhoben. Die nativen Bibliotheken stehen erst "
    "nach dem PyInstaller-Lauf fest und werden aus den fertigen Binaries gelesen. "
    "Die leere Liste bedeutet NICHT, dass keine nativen Bestandteile mitgeliefert "
    "werden."
)

#: Die drei Zustaende der Ebene ``nativ``. Sie stehen im Feld ``zustand`` und sind
#: dort unterscheidbar, ohne dass eine Anzeige aus leeren Listen raten muesste.
NATIV_NICHT_ANGEFORDERT: Final = "nicht_angefordert"
NATIV_ERHOBEN: Final = "erhoben"
NATIV_OHNE_PAKETVERZEICHNIS: Final = "kein_paketverzeichnis"

#: Der dritte Zustand: die Erhebung wurde angefordert, aber auf der Zielplattform
#: gibt es keine Datei-zu-Paket-Zuordnung. Ohne sie fehlt die Quelle, aus der
#: Systempaket, Bezeichner und Lizenztext hervorgingen. Der Wortlaut beschreibt
#: ausschliesslich, was dieses Werkzeug auf dieser Plattform ermitteln kann; ueber
#: die Rechte an den Bibliotheken sagt er nichts.
EBENE_NATIV_OHNE_PAKETVERZEICHNIS: Final = (
    "Angefordert, aber auf der Zielplattform {plattform} nicht ermittelbar: dort "
    "steht keine Datei-zu-Paket-Zuordnung zur Verfuegung, aus der sich das "
    "liefernde Systempaket und dessen Lizenztext belegen liessen. Die leere Liste "
    "ist eine Aussage ueber die Ermittelbarkeit auf dieser Plattform, NICHT darueber, "
    "welche nativen Bestandteile mitgeliefert werden und unter welchen Bedingungen "
    "sie stehen."
)

#: Die Zielplattform, fuer die die Aufstellung erzeugt wird. Sie wird NICHT aus der
#: laufenden Maschine geraten, sondern ueber ``--zielplattform`` uebergeben. Die
#: Vorgabe ist ``linux-x86_64``: ein Aufruf ohne den Schalter verhaelt sich damit
#: genau wie bisher, als beide Werte feste Konstanten waren.
ZIELPLATTFORM_VORGABE: Final = "linux-x86_64"

#: Je Zielplattform das Rust-Ziel (``cargo tree --target``), die Endungen nativer
#: Bibliotheken (Ebene ``nativ``) und ob es auf dieser Plattform ueberhaupt eine
#: Datei-zu-Paket-Zuordnung gibt, aus der Systempaket und Lizenztext hervorgehen.
#:
#: ``paketverzeichnis``: Der Name des Werkzeugs, das die Paketdatenbank des Systems
#: befragt. ``None`` heisst: auf dieser Plattform gibt es keine solche Datenbank.
#: Das ist kein Fehler, sondern eine Eigenschaft der Plattform -- siehe
#: ``EBENE_NATIV_OHNE_PAKETVERZEICHNIS``.
ZIELPLATTFORMEN: Final[dict[str, dict[str, Any]]] = {
    "linux-x86_64": {
        "rust_ziel": "x86_64-unknown-linux-gnu",
        "bibliotheksendungen": (".so",),
        "paketverzeichnis": "dpkg-query",
    },
    "windows-x86_64": {
        "rust_ziel": "x86_64-pc-windows-msvc",
        "bibliotheksendungen": (".dll", ".pyd"),
        "paketverzeichnis": None,
    },
    "windows-aarch64": {
        "rust_ziel": "aarch64-pc-windows-msvc",
        "bibliotheksendungen": (".dll", ".pyd"),
        "paketverzeichnis": None,
    },
    "macos-x86_64": {
        "rust_ziel": "x86_64-apple-darwin",
        "bibliotheksendungen": (".dylib",),
        "paketverzeichnis": None,
    },
    "macos-aarch64": {
        "rust_ziel": "aarch64-apple-darwin",
        "bibliotheksendungen": (".dylib",),
        "paketverzeichnis": None,
    },
}

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
# Werkzeuge und Verzeichnisse der laufenden Maschine
# --------------------------------------------------------------------------------


def werkzeugpfad(name: str) -> str:
    """Sucht ein Werkzeug im PATH und liefert seinen vollstaendigen Pfad.

    Der aufzurufende Dateiname ist plattformabhaengig: unter Windows heisst ``npm``
    tatsaechlich ``npm.cmd``, und eine ``.cmd`` laesst sich ohne ihre Endung nicht
    starten. ``shutil.which`` loest das ueber ``PATHEXT`` und liefert den Namen, der
    sich wirklich ausfuehren laesst -- deshalb wird hier immer der GEFUNDENE Pfad
    verwendet, nie der blosse Name.

    Fehlt das Werkzeug, ist das ein harter Abbruch. Ohne ``npm`` bliebe die Ebene
    ``npm`` leer, ohne dass die Datei das kenntlich machte -- genau der stille
    Rueckfall, den dieses Werkzeug nicht kennen darf.
    """
    pfad = shutil.which(name)
    if pfad is None:
        raise SystemExit(
            f"{name} wurde im PATH nicht gefunden. Ohne dieses Werkzeug laesst sich "
            "die zugehoerige Ebene nicht erheben; eine leere Ebene waere ein stiller "
            "Rueckfall und ist nicht zulaessig."
        )
    return pfad


def finde_sitepackages(wurzel: Path) -> Path:
    """Ermittelt das ``site-packages`` des Repo-venv, ohne ein Layout zu raten.

    Das Layout ist plattformabhaengig: POSIX legt die Pakete unter
    ``lib/python3.12/site-packages``, Windows unter ``Lib/site-packages``. Beides
    fest zu verdrahten hiesse raten -- gefragt wird deshalb ``sysconfig``, das die
    Regel des jeweiligen Laufzeitsystems kennt, und geprueft wird, was wirklich da
    ist.

    Findet sich kein Verzeichnis, ist das ein harter Abbruch: ein ``glob`` auf ein
    nicht vorhandenes Verzeichnis liefert lautlos nichts, und die Ebene ``python``
    bliebe leer, ohne dass die Datei den Ausfall kenntlich machte (Regel 2).
    """
    venv = wurzel / ".venv"
    kandidaten: list[Path] = []

    # Erster Rang: die Regel des laufenden Python fuer ein venv an diesem Ort.
    for schema in ("venv", "nt_venv", "posix_venv"):
        if schema not in sysconfig.get_scheme_names():
            continue
        try:
            roh = sysconfig.get_path("purelib", schema, vars={"base": str(venv)})
        except KeyError:
            continue
        pfad = Path(roh)
        if pfad not in kandidaten:
            kandidaten.append(pfad)

    # Zweiter Rang: die beiden bekannten Layouts, direkt nachgesehen. Der
    # Sternchen-Teil deckt eine andere Python-Fassung im venv ab.
    for gemustert in sorted(venv.glob("lib/python*/site-packages")):
        if gemustert not in kandidaten:
            kandidaten.append(gemustert)
    for fest in (venv / "Lib" / "site-packages", venv / "lib" / "site-packages"):
        if fest not in kandidaten:
            kandidaten.append(fest)

    for pfad in kandidaten:
        if pfad.is_dir():
            return pfad
    raise SystemExit(
        f"Kein site-packages-Verzeichnis unter {venv} gefunden. Ohne die installierten "
        "Paketmetadaten laesst sich die Ebene python nicht erheben; eine leere Ebene "
        "waere ein stiller Rueckfall und ist nicht zulaessig."
    )


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
            werkzeugpfad("uv"),
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--no-hashes",
        ],
        cwd=wurzel,
        capture_output=True,
        text=True,
        encoding="utf-8",
        # Reiner Maschinentext: Namen und Fassungen gelockter Pakete, aus denen
        # nur ueber ein ASCII-Muster Name und Version gelesen werden. Ein
        # Ersatzzeichen kann hier keine Lizenzangabe verfaelschen -- aus dieser
        # Ausgabe stammt keine.
        errors="replace",
        check=True,
    ).stdout
    gelockt: dict[str, str] = {}
    for zeile in ausgabe.splitlines():
        treffer = re.match(r"^([A-Za-z0-9._-]+)==([^\s;]+)", zeile.strip())
        if treffer:
            gelockt[_pep503(treffer.group(1))] = treffer.group(2)

    # Existenzforderung, nicht blosse Abfrage: das Lock MUSS produktive Pakete
    # erklaeren. Es ist der einzige Massstab, an dem sich die Ebene python messen
    # laesst -- ohne ihn liesse sich eine leere Ebene nicht von einer
    # vollstaendigen unterscheiden, und der Waechter weiter unten liefe mangels
    # Vergleichsgroesse still durch. Er wuerde damit genau die Lage decken, gegen
    # die er steht (Finding S3).
    if not gelockt:
        raise SystemExit(
            "Ebene python: 'uv export --frozen --no-dev' nennt kein einziges "
            "produktives Paket. Ohne diese Erklaerung gibt es keinen Massstab "
            "dafuer, was mitgeliefert wird; eine leere Ebene python liesse sich "
            "dann nicht von einer vollstaendigen unterscheiden. Entweder ist die "
            "Lock-Datei beschaedigt, oder das Projekt hat keine produktiven "
            "Abhaengigkeiten mehr -- dann gehoert die Ebene python aus erzeuge "
            "entfernt."
        )

    sitepackages = finde_sitepackages(wurzel)
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

    # Waechter, gebaut auf dem Vergleich gelockt gegen gefunden -- demselben, den
    # sammle_npm zwischen package.json und 'npm ls' zieht. Das Lock erklaert
    # produktive Pakete, unter site-packages traegt aber keines davon eine
    # dist-info-Metadatei: dann ist das Verzeichnis zwar da, aber leer oder fremd
    # bestueckt. Ohne diesen Waechter liefe der Sammler still mit null Eintraegen
    # durch, und die Aufstellung behauptete eine Vollstaendigkeit, die sie nicht
    # hat. finde_sitepackages faengt nur den Fall ab, dass das Verzeichnis fehlt.
    if not gefunden:
        raise SystemExit(
            f"Ebene python: das Lock erklaert {len(gelockt)} produktive(s) Paket(e) "
            f"({', '.join(sorted(gelockt))}), unter {sitepackages} traegt aber "
            "keines davon eine lesbare dist-info-Metadatei. Naechstliegende "
            "Ursache: die Umgebung ist nicht eingerichtet oder gehoert zu einem "
            "anderen Projekt. Die Bestandteile werden dennoch mitgeliefert -- die "
            "Ebene python bliebe leer, und die Aufstellung behauptete eine "
            "Vollstaendigkeit, die sie nicht hat. Abhilfe: 'uv sync' im "
            f"Verzeichnis {wurzel} und erneut erzeugen."
        )

    # TEILWEISE Erhebung: gemeldet, aber nicht abgebrochen -- und ohne Schwelle.
    # Gemessener Normalfall auf linux-x86_64: 51 gelockte, 48 erhobene Pakete. Die
    # Luecke von dreien ist kein Ausfall, sondern der Bestand, den das Lock unter
    # dem Marker sys_platform == 'win32' fuehrt (colorama, pywin32-ctypes,
    # tzdata); er ist hier nicht installiert und wird hier nicht mitgeliefert. Der
    # Abstand ist damit eine Eigenschaft des Abhaengigkeitsbestands, keine der
    # Installation: er verschiebt sich mit jedem Paket, das mit Marker hinzukommt
    # oder wegfaellt. Eine Schwelle darauf waere entweder so eng, dass sie beim
    # naechsten markierten Paket im Normalbetrieb falsch anschlaegt -- schlimmer
    # als kein Waechter --, oder so weit, dass sie nichts mehr faengt. Statt einer
    # Zahl steht deshalb die NAMENTLICHE Nennung der fehlenden Pakete: sie ist
    # aussagekraeftiger als jede Quote und laesst den Leser selbst entscheiden.
    # Die Meldung geht auf die Konsole, nicht in die Datei -- die Aufstellung
    # fuehrt nur, was mitgeliefert wird.
    fehlend = sorted(set(gelockt) - gefunden)
    if fehlend:
        print(
            f"Hinweis Ebene python: {len(gefunden)} von {len(gelockt)} gelockten "
            f"Paketen erhoben. Nicht installiert und daher nicht mitgeliefert: "
            f"{', '.join(fehlend)}"
        )


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
    try:
        ergebnis = subprocess.run(
            [werkzeugpfad("npm"), "ls", "--omit=dev", "--all", "--json"],
            cwd=verzeichnis,
            capture_output=True,
            text=True,
            encoding="utf-8",
            # KEIN errors="replace": aus diesem Baum stammen die Pfade der Pakete,
            # unter denen anschliessend die Lizenzdateien gelesen werden. Ein
            # Ersatzzeichen in einem Pfad liesse die Lizenzdatei stumm ins Leere
            # laufen, und der Eintrag stuende ohne Text da -- eine verfaelschte
            # Lizenzangabe. Deshalb strikt und im Zweifel Abbruch.
            errors="strict",
            check=False,
        )
    except UnicodeDecodeError as fehler:
        raise SystemExit(
            f"npm ls in {verzeichnis} lieferte keine gueltige UTF-8-Ausgabe "
            f"({fehler}). Der Baum nennt die Pfade, unter denen die Lizenzdateien "
            "gelesen werden -- ein Ersatzzeichen darin wuerde eine Lizenzangabe "
            "verfaelschen."
        ) from fehler
    # npm meldet bei fehlenden optionalen Peers einen Fehlercode, liefert den Baum
    # aber trotzdem -- deshalb wird der Code hier nicht geprueft. Er unterscheidet
    # nicht zwischen diesem harmlosen Fall und einem fehlenden node_modules, das
    # denselben Code (ELSPROBLEMS) traegt. Diese Unterscheidung trifft der Waechter
    # in sammle_npm, der die erklaerten produktiven Abhaengigkeiten gegen das
    # Ergebnis haelt; ein unlesbarer Baum faellt schon hier.
    return json.loads(ergebnis.stdout) if ergebnis.stdout.strip() else {}


def _npm_flach(baum: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Klopft den npm-Abhaengigkeitsbaum zu einer flachen Zuordnung auseinander.

    Eintraege ohne aufgeloeste Fassung werden uebergangen. Dahinter stehen zwei
    Faelle, die diesem Baum nicht anzusehen sind: ein unerfuellter optionaler Peer
    -- der ist nicht installiert, wird nicht ausgeliefert und gehoert nicht in die
    Aufstellung -- oder ein fehlendes beziehungsweise unvollstaendiges
    ``node_modules``: dann nennt ``npm ls`` die erklaerte Abhaengigkeit ohne
    Fassung, obwohl sie ausgeliefert wird. Der zweite Fall darf nicht als der erste
    durchgehen. Unterschieden wird er nicht hier, sondern vom Waechter in
    :func:`sammle_npm`, der die in der ``package.json`` erklaerten produktiven
    Abhaengigkeiten gegen das Ergebnis haelt.
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


def _npm_erklaerte_abhaengigkeiten(herkunft: str, verzeichnis: Path) -> dict[str, Any]:
    """Liest die produktiven Abhaengigkeiten der ``package.json`` eines npm-Ortes.

    Existenzforderung, nicht blosse Abfrage: an beiden Orten, die
    :func:`sammle_npm` liest, MUSS eine ``package.json`` liegen, und dort MUESSEN
    produktive Abhaengigkeiten erklaert sein -- beide Orte sind fest verdrahtet,
    weil beide erklaertermassen Fremdbestandteile mitliefern. Fehlt die Datei, ist
    sie unlesbar oder nennt sie kein gefuelltes ``dependencies``, faellt das
    Werkzeug. Ein Waechter, der mangels Fundstelle still durchliefe, waere kein
    Waechter: er wuerde genau die Lage decken, gegen die er steht (Finding S3).

    Gelesen wird ausschliesslich ``dependencies``. ``devDependencies`` werden nicht
    ausgeliefert (``npm ls --omit=dev``), und ``optionalDependencies`` duerfen
    zulaessig unaufgeloest bleiben -- beide taugen nicht als Massstab dafuer, dass
    etwas mitgeliefert wird.
    """
    paketjson = verzeichnis / "package.json"
    stelle = f"npm-Ort {herkunft} ({paketjson})"
    if not paketjson.is_file():
        raise SystemExit(
            f"{stelle}: keine package.json gefunden. Dieser Ort liefert "
            "Fremdbestandteile mit; ohne seine package.json laesst sich nicht "
            "pruefen, ob die Ebene npm vollstaendig ist. Eine ungeprueft "
            "durchgelassene Ebene waere ein stiller Rueckfall."
        )
    roh = lies_text(paketjson)
    if roh is None:
        raise SystemExit(f"{stelle}: package.json ist nicht lesbar.")
    try:
        angaben = json.loads(roh)
    except json.JSONDecodeError as fehler:
        raise SystemExit(f"{stelle}: package.json ist kein gueltiges JSON ({fehler}).") from fehler
    erklaert = angaben.get("dependencies")
    if not isinstance(erklaert, dict) or not erklaert:
        raise SystemExit(
            f"{stelle}: package.json erklaert keine produktiven Abhaengigkeiten "
            "(Feld 'dependencies' fehlt, ist leer oder kein Objekt). An diesem Ort "
            "muessen welche stehen -- er ist als Quelle mitgelieferter "
            "Fremdbestandteile fest verdrahtet. Entweder ist die Datei beschaedigt, "
            "oder der Ort ist entfallen und gehoert aus sammle_npm entfernt."
        )
    return erklaert


def sammle_npm(sammler: Sammler, wurzel: Path) -> None:
    """Produktive Huelle des Frontends plus die Wurzelabhaengigkeit."""
    orte = [("frontend", wurzel / "frontend"), ("wurzel", wurzel)]
    gesehen: set[tuple[str, str]] = set()
    for herkunft, verzeichnis in orte:
        erklaert = _npm_erklaerte_abhaengigkeiten(herkunft, verzeichnis)
        flach = _npm_flach(_npm_baum(verzeichnis))
        if not flach:
            raise SystemExit(
                f"npm-Ort {herkunft} ({verzeichnis}): die package.json erklaert "
                f"{len(erklaert)} produktive Abhaengigkeit(en) "
                f"({', '.join(sorted(erklaert))}), 'npm ls --omit=dev' loest davon "
                "aber keine einzige zu einer Fassung auf. Naechstliegende Ursache: "
                "node_modules fehlt oder ist unvollstaendig. Die Bestandteile werden "
                "dennoch mitgeliefert -- die Ebene npm bliebe leer, und die "
                "Aufstellung behauptete eine Vollstaendigkeit, die sie nicht hat. "
                f"Abhilfe: 'npm install' in {verzeichnis} und erneut erzeugen."
            )
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


def sammle_rust(sammler: Sammler, wurzel: Path, rust_ziel: str) -> None:
    """Die Crates des angegebenen Rust-Ziels, Lizenztext aus dem Registry-Cache."""
    manifest = wurzel / "src-tauri" / "Cargo.toml"
    cargo = werkzeugpfad("cargo")
    try:
        rohmetadaten = subprocess.run(
            [
                cargo,
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--manifest-path",
                str(manifest),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            # KEIN errors="replace": diese Ausgabe fuehrt die Lizenzangaben selbst
            # -- ``license`` (der Bezeichner), ``authors`` (der Urhebervermerk) und
            # ``manifest_path`` (das Verzeichnis, aus dem der Lizenztext gelesen
            # wird). Urhebervermerke tragen regelmaessig Umlaute und Akzente; ein
            # Ersatzzeichen darin waere ein verfaelschter Vermerk. Deshalb strikt.
            errors="strict",
            check=True,
        ).stdout
    except UnicodeDecodeError as fehler:
        raise SystemExit(
            f"cargo metadata lieferte keine gueltige UTF-8-Ausgabe ({fehler}). Die "
            "Ausgabe fuehrt Bezeichner, Urhebervermerke und Pfade der Lizenzdateien "
            "-- ein Ersatzzeichen darin wuerde eine Lizenzangabe verfaelschen."
        ) from fehler
    metadaten = json.loads(rohmetadaten)
    baum = subprocess.run(
        [
            cargo,
            "tree",
            "--locked",
            "--manifest-path",
            str(manifest),
            "--target",
            rust_ziel,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--no-dedupe",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        # Reiner Maschinentext: aus dieser Ausgabe wird ausschliesslich ueber ein
        # ASCII-Muster (``name vfassung``) gelesen, welche Crates im Ziel liegen.
        # Bezeichner, Text und Vermerk stammen samtlich aus cargo metadata, nicht
        # von hier -- ein Ersatzzeichen kann keine Lizenzangabe verfaelschen. Es
        # koennte allenfalls einen Crate-Namen unlesbar machen; der faellt dann in
        # sortierter Zuordnung auf und wuerde nicht still falsch zugeordnet, weil
        # der Name nur mit den Namen aus cargo metadata abgeglichen wird.
        errors="replace",
        check=True,
    ).stdout

    eigenes = {(p["name"], p["version"]) for p in metadaten["packages"] if p.get("source") is None}
    nach_kennung = {(p["name"], p["version"]): p for p in metadaten["packages"]}
    im_ziel: set[tuple[str, str]] = set()
    for zeile in baum.splitlines():
        treffer = re.match(r"^([A-Za-z0-9_.+-]+) v([^\s]+)", zeile.strip())
        if treffer:
            im_ziel.add((treffer.group(1), treffer.group(2)))
    im_ziel -= eigenes

    # Waechter der Ebene rust, gebaut wie die drei bestehenden Ebenen-Waechter: das
    # Lock erklaert den Bestand, das Werkzeug loest ihn auf, und der Vergleich
    # beider Groessen macht eine leere Ebene von einer vollstaendigen
    # unterscheidbar. Ohne ihn liefe der Sammler mit null rust-Eintraegen still
    # durch, und die Aufstellung behauptete eine Vollstaendigkeit, die sie nicht hat.
    #
    # Die Meldung TRENNT die beiden Ursachen, weil sie zu verschiedenen Abhilfen
    # fuehren: gab 'cargo metadata' schon keine Fremdpakete her, ist die Erhebung
    # gar nicht erst gelaufen (Lock leer, Manifest ohne Abhaengigkeiten); nannte
    # sie welche und liefert erst 'cargo tree --target' nichts, dann lief das
    # Werkzeug, fand aber fuer DIESES Ziel nichts -- ein falsches oder auf dieser
    # Plattform leeres Rust-Ziel.
    fremde = {kennung for kennung in nach_kennung if kennung not in eigenes}
    if not fremde:
        raise SystemExit(
            f"Ebene rust: 'cargo metadata --locked' zu {manifest} nennt kein "
            "einziges FREMDES Paket -- die Erhebung ist nicht gelaufen, nicht "
            "bloss ergebnislos geblieben. Ohne diese Erklaerung gibt es keinen "
            "Massstab dafuer, was mitgeliefert wird; eine leere Ebene rust liesse "
            "sich dann nicht von einer vollstaendigen unterscheiden. "
            "Naechstliegende Ursache: Cargo.lock ist beschaedigt oder das Manifest "
            "fuehrt keine Abhaengigkeiten mehr -- dann gehoert die Ebene rust aus "
            "erzeuge entfernt."
        )
    if not im_ziel:
        raise SystemExit(
            f"Ebene rust: 'cargo metadata' nennt {len(fremde)} fremde(s) Paket(e), "
            f"'cargo tree --target {rust_ziel}' loest davon aber keines zu einer "
            "Fassung auf. Das Werkzeug lief und fand fuer DIESES Ziel nichts -- "
            "anders als der Fall, dass gar nichts erhoben wurde. Naechstliegende "
            f"Ursache: das Rust-Ziel {rust_ziel} ist falsch geschrieben oder auf "
            "dieser Plattform nicht bestueckt. Die Crates werden dennoch "
            "mitgeliefert -- die Ebene rust bliebe leer, und die Aufstellung "
            "behauptete eine Vollstaendigkeit, die sie nicht hat."
        )

    erhoben = 0
    for kennung in sorted(im_ziel):
        paket = nach_kennung.get(kennung)
        if paket is None:
            continue
        erhoben += 1
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

    # Dritter Fall, von den beiden oberen verschieden: das Ziel nennt Crates, aber
    # keine davon liess sich in den Metadaten wiederfinden -- dann entstand trotz
    # gelaufener Erhebung kein einziger Eintrag. Dieselbe Bauart wie der
    # Schluss-Waechter der Ebene nativ ("gefunden und doch keine Eintraege").
    if not erhoben:
        raise SystemExit(
            f"Ebene rust: 'cargo tree --target {rust_ziel}' nennt {len(im_ziel)} "
            "Crate(s), zu keiner einzigen davon fuehrt 'cargo metadata' aber einen "
            "Datensatz -- es entstand kein Eintrag. Beide Werkzeuge liefen, ihre "
            "Ergebnisse passen jedoch nicht zusammen. Naechstliegende Ursache: "
            "Baum und Metadaten stammen aus verschiedenen Staenden des Manifests "
            f"{manifest}. Eine leere Ebene rust bei gelaufener Erhebung ist ein "
            "stiller Rueckfall und nicht zulaessig."
        )


# --------------------------------------------------------------------------------
# Ebenen daten und programme
# --------------------------------------------------------------------------------


def sammle_daten(sammler: Sammler, wurzel: Path) -> None:
    """Die Bestaende unter backend/data und frontend/public/flags.

    Existenzforderung, nicht blosse Abfrage: ``DATENBESTAENDE`` MUSS Bestaende
    fuehren, und jeder genannte Pfad MUSS vorhanden sein. Diese Ebene laeuft nicht
    ueber eine Erhebung, sondern ueber eine von Hand gefuehrte Liste -- sie kann
    nichts auslassen, aber sie kann etwas behaupten. Faellt ein Bestand weg, ohne
    dass die Liste nachgezogen wird, stuende er weiter mit ``mitgeliefert=true`` in
    der Aufstellung: keine stille Auslassung, sondern eine stille
    Falschbehauptung, und nach Finding S3 derselbe Verstoss. Deshalb faellt das
    Werkzeug hier, statt eine Angabe zu fuehren, die es nicht belegen kann.

    Geprueft wird auf blosse Existenz, nicht auf Dateiart: die Bestaende sind teils
    Dateien (``oui.json``), teils Verzeichnisse (``frontend/public/flags``).
    """
    if not DATENBESTAENDE:
        raise SystemExit(
            "Ebene daten: DATENBESTAENDE fuehrt keinen einzigen Bestand. Diese "
            "Liste ist die einzige Quelle der Ebene; ist sie leer, entsteht "
            "lautlos eine leere Ebene, ohne dass die Aufstellung den Ausfall "
            "kenntlich machte. Entweder ist die Liste versehentlich geleert "
            "worden, oder es werden keine Datenbestaende mehr mitgeliefert -- dann "
            "gehoert die Ebene daten aus erzeuge entfernt."
        )
    for bestand in DATENBESTAENDE:
        bestandspfad = wurzel / str(bestand["pfad"])
        if not bestandspfad.exists():
            raise SystemExit(
                f"Ebene daten: der Bestand {bestand['name']!r} ist unter "
                f"{bestandspfad} nicht vorhanden. Die Aufstellung wuerde ihn mit "
                "mitgeliefert=true fuehren und damit behaupten, es werde etwas "
                "ausgeliefert, das nicht da ist. Entweder fehlt der Bestand im "
                "Arbeitsbaum, oder er ist entfallen und gehoert aus DATENBESTAENDE "
                "entfernt."
            )
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
# Ebene nativ: die mitgelieferten nativen Bibliotheken der PyInstaller-Binaries
# --------------------------------------------------------------------------------

# Der entscheidende Zeitpunkt: welche nativen Bibliotheken mitgeliefert werden,
# ergibt sich aus der Abhaengigkeitsanalyse von PyInstaller. Sie steht erst fest,
# wenn die Binaries gebaut sind. Deshalb wird diese Ebene nicht aus dem Quellbaum
# erhoben, sondern aus dem CArchive der fertigen Binaries -- REIN LESEND. Die
# Binaries werden dabei nicht entpackt und nicht ausgefuehrt; gelesen werden allein
# das Inhaltsverzeichnis (TOC) und daraus Dateiname und Groesse.

#: Das Erkennungsmuster ("Cookie") am Ende eines PyInstaller-Binaries. Ihm folgen
#: Gesamtlaenge des Archivs, Lage und Laenge des Inhaltsverzeichnisses.
#: Vgl. ``PyInstaller.archive.readers.CArchiveReader``; das Format wird hier
#: nachgebildet, damit das Werkzeug ohne PyInstaller auskommt (nur stdlib).
CARCHIVE_MAGIE: Final = b"MEI\014\013\012\013\016"
CARCHIVE_KOPF_FORMAT: Final = "!8sIIII64s"
CARCHIVE_EINTRAG_FORMAT: Final = "!IIIIBc"
CARCHIVE_SUCHBLOCK: Final = 8192

#: Der Typkennbuchstabe der TOC-Eintraege, die eine mitgelieferte Binaerdatei
#: bezeichnen (``PKG_ITEM_BINARY``). Nur diese kommen als native Bibliothek in
#: Frage; Quelltext, Datendateien und das Python-Archiv tragen andere Buchstaben.
CARCHIVE_TYP_BINAER: Final = "b"

#: Eine native Bibliothek traegt eine SONAME-artige Endung. Erweiterungsmodule von
#: Python-Paketen (``_imaging.cpython-312-x86_64-linux-gnu.so``,
#: ``_rust.abi3.so``) sind KEINE eigenstaendigen Bibliotheken -- sie sind
#: Bestandteil ihres Python-Pakets und dort auf der Ebene ``python`` bereits
#: gefuehrt. Sie hier erneut aufzunehmen hiesse, sie doppelt zu fuehren.
#:
#: Dieselben Module heissen je nach Plattform anders: unter Linux und macOS
#: ``.cpython-312-...so`` bzw. ``...dylib``, unter Windows ``.cp312-win_amd64.pyd``
#: und ``.pyd``. Der Windows-Teil ist mit dem Bibliotheksfilter aus A4 hinzugekommen
#: -- ohne ihn geriete unter Windows jedes Erweiterungsmodul in die Ebene ``nativ``,
#: obwohl es auf der Ebene ``python`` bereits steht.
#:
#: KEIN ``re.IGNORECASE``: das Flag wirkt auf den GESAMTEN Ausdruck, also auch auf
#: den ``.so``-Teil. Ein Name auf ``.SO`` waere damit unter Linux ploetzlich
#: ausgeschlossen, obwohl er es vorher nicht war -- eine Verhaltensaenderung auf
#: der Zielplattform und ein Widerspruch zu ``ist_native_bibliothek``, die
#: ausdruecklich zeichengetreu vergleicht. Der ``.so``-Teil bleibt deshalb
#: zeichengetreu und das Linux-Ergebnis unveraendert.
#:
#: Gross- und Kleinschreibung wird ausschliesslich dort beruecksichtigt, wo sie
#: hingehoert: in den Windows- und macOS-Formen. Windows-Dateisysteme
#: unterscheiden sie nicht, ``FOO.PYD`` und ``foo.pyd`` bezeichnen dieselbe Datei;
#: macOS-Dateisysteme sind in der Vorgabe ebenfalls nicht unterscheidend. Die
#: Buchstabenklassen stehen daher nur in diesen beiden Teilen -- Zeichen fuer
#: Zeichen ausgeschrieben, statt ueber ein Flag, das den ganzen Ausdruck ergriffe.
PYTHON_ERWEITERUNG_MUSTER: Final = re.compile(
    # Linux: zeichengetreu, unveraendert gegenueber dem Stand vor der
    # Plattform-Erweiterung.
    r"\.(?:cpython-\d+[^.]*|abi\d+|pypy\d+[^.]*)\.so$"
    # macOS: dieselben Kennungen, Endung .dylib in beliebiger Schreibung.
    r"|\.(?:[cC][pP][yY][tT][hH][oO][nN]-\d+[^.]*|[aA][bB][iI]\d+|[pP][yY][pP][yY]\d+[^.]*)"
    r"\.[dD][yY][lL][iI][bB]$"
    # Windows: .cp312-win_amd64.pyd, .pypy311-...pyd und das blosse .pyd.
    r"|\.(?:[cC][pP]\d+-[^.]*|[pP][yY][pP][yY]\d+[^.]*)?\.?[pP][yY][dD]$",
)

#: Der Ordner, in den ``auditwheel`` die von einem Python-Rad mitgebrachten
#: Bibliotheken legt. Der Name traegt einen Hash (``libjpeg-8296d2fa.so.62.4.0``),
#: es gibt also kein Systempaket dazu -- diese Bibliotheken teilen die Lizenz ihres
#: Python-Pakets (Punkt 1f des Auftrags) und werden diesem zugeordnet.
RAD_BIBLIOTHEKSORDNER_MUSTER: Final = re.compile(r"^(?P<paket>[A-Za-z0-9_.-]+)\.libs/")

#: Erkennt eine ``copyright``-Datei im maschinenlesbaren Debian-Format (DEP-5).
#: Nur dort sind ``License:`` und ``Copyright:`` ausgewiesene Felder. In den
#: Freitext-Fassungen stehen dieselben Woerter mitten im Fliesstext; sie dort als
#: Bezeichner oder Vermerk zu lesen waere eine Deutung, kein Beleg (Regel 2).
DEP5_KOPF_MUSTER: Final = re.compile(
    r"^Format:\s*\S*copyright-format/1\.0/?\s*$",
    re.MULTILINE,
)

#: Der Absatz, der fuer das Paket als Ganzes gilt.
DEP5_ALLE_DATEIEN_MUSTER: Final = re.compile(r"^Files:\s*\*\s*$", re.MULTILINE)

#: Ein DEP-5-Feld: Wert in derselben Zeile, Fortsetzungszeilen eingerueckt.
DEP5_FELD_MUSTER: Final = r"^{feld}:[ \t]*(?P<wert>.*(?:\n[ \t]+\S.*)*)$"


class CArchiveFehler(Exception):
    """Das Binaerformat war nicht lesbar. Kein stiller Rueckfall -- ein Fehler."""


def lies_carchive_verzeichnis(binaer: Path) -> list[tuple[str, str, int]]:
    """Liest das Inhaltsverzeichnis eines PyInstaller-Binaries, rein lesend.

    Liefert je Eintrag Name, Typkennbuchstaben und die entpackte Groesse in Bytes.
    Es wird nichts entpackt und nichts ausgefuehrt: die Nutzdaten selbst bleiben
    ungelesen, gelesen werden nur Kopf und Inhaltsverzeichnis.
    """
    kopflaenge = struct.calcsize(CARCHIVE_KOPF_FORMAT)
    eintragslaenge = struct.calcsize(CARCHIVE_EINTRAG_FORMAT)
    with binaer.open("rb") as strom:
        beginn = _finde_carchive_magie(strom)
        if beginn < 0:
            raise CArchiveFehler(f"{binaer}: kein PyInstaller-Archiv (Magie nicht gefunden)")
        strom.seek(beginn)
        kopf = strom.read(kopflaenge)
        if len(kopf) != kopflaenge:
            raise CArchiveFehler(f"{binaer}: Archivkopf unvollstaendig")
        _, archivlaenge, tabelle_lage, tabelle_laenge, _, _ = struct.unpack(
            CARCHIVE_KOPF_FORMAT, kopf
        )
        archivbeginn = beginn + kopflaenge - archivlaenge
        strom.seek(archivbeginn + tabelle_lage)
        rohtabelle = strom.read(tabelle_laenge)
    if len(rohtabelle) != tabelle_laenge:
        raise CArchiveFehler(f"{binaer}: Inhaltsverzeichnis unvollstaendig")

    eintraege: list[tuple[str, str, int]] = []
    stelle = 0
    while stelle < len(rohtabelle):
        block = rohtabelle[stelle : stelle + eintragslaenge]
        if len(block) != eintragslaenge:
            raise CArchiveFehler(f"{binaer}: abgeschnittener Eintrag im Inhaltsverzeichnis")
        gesamtlaenge, _, _, entpackte_laenge, _, typ = struct.unpack(CARCHIVE_EINTRAG_FORMAT, block)
        namenslaenge = gesamtlaenge - eintragslaenge
        if namenslaenge < 0:
            raise CArchiveFehler(f"{binaer}: unplausible Eintragslaenge {gesamtlaenge}")
        stelle += eintragslaenge
        rohname = rohtabelle[stelle : stelle + namenslaenge]
        stelle += namenslaenge
        name = rohname.rstrip(b"\0").decode("utf-8", errors="replace")
        eintraege.append((name, typ.decode("ascii", errors="replace"), entpackte_laenge))
    return eintraege


def _finde_carchive_magie(strom: BinaryIO) -> int:
    """Sucht die Erkennungsmarke vom Dateiende her rueckwaerts."""
    strom.seek(0, os.SEEK_END)
    ende = strom.tell()
    while ende >= len(CARCHIVE_MAGIE):
        anfang = max(ende - CARCHIVE_SUCHBLOCK, 0)
        laenge = ende - anfang
        if laenge < len(CARCHIVE_MAGIE):
            break
        strom.seek(anfang)
        block = strom.read(laenge)
        stelle = block.rfind(CARCHIVE_MAGIE)
        if stelle != -1:
            return anfang + stelle
        ende = anfang + len(CARCHIVE_MAGIE) - 1
    return -1


def ist_native_bibliothek(
    name: str,
    endungen: Sequence[str] = (".so",),
) -> bool:
    """Sagt, ob ein TOC-Name eine eigenstaendige native Bibliothek bezeichnet.

    Welche Endung eine native Bibliothek traegt, haengt an der ZIELplattform, nicht
    an der Maschine, auf der dieses Werkzeug laeuft: ``.so`` unter Linux, ``.dylib``
    unter macOS, ``.dll`` und ``.pyd`` unter Windows. Die Endungen kommen deshalb
    aus ``ZIELPLATTFORMEN`` und werden hier uebergeben. Die Vorgabe ``(".so",)``
    haelt das bisherige Verhalten fest.

    Die Form ``libfoo.so.6`` (SONAME mit Fassungsnummer) gibt es nur bei ``.so`` und
    ``.dylib``; unter Windows steht die Fassung im Dateinamen selbst. Beide Formen
    werden geprueft, die zweite laeuft unter Windows schlicht ins Leere.

    Verglichen wird zeichengetreu, ohne Angleichung der Gross-/Kleinschreibung: auf
    einem Dateisystem, das zwischen ``.so`` und ``.SO`` unterscheidet, waere eine
    unscharfe Pruefung eine Verhaltensaenderung.
    """
    if PYTHON_ERWEITERUNG_MUSTER.search(name) is not None:
        return False
    dateiname = name.rsplit("/", 1)[-1]
    return any(dateiname.endswith(endung) or f"{endung}." in dateiname for endung in endungen)


def _paket_zu_datei(dateiname: str, paketverzeichnis: str) -> str | None:
    """Fragt die Paketdatenbank des Systems, welches Paket eine Datei liefert.

    Verwendet ``dpkg-query -S``. Findet sich keine Zuordnung, ist das Ergebnis
    ``None`` -- es wird nichts geraten (Regel 2).
    """
    try:
        ergebnis = subprocess.run(
            [werkzeugpfad(paketverzeichnis), "-S", f"*/{dateiname}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            # KEIN errors="replace": aus dieser Ausgabe kommt der Paketname, und aus
            # ihm werden Bezeichner, Urhebervermerk und Lizenztext gelesen
            # (/usr/share/doc/<paket>/copyright). Ein Ersatzzeichen im Namen fuehrte
            # auf ein anderes oder auf gar kein Paket -- also auf einen fremden oder
            # fehlenden Lizenztext. Deshalb strikt.
            errors="strict",
            check=False,
        )
    except UnicodeDecodeError as fehler:
        raise SystemExit(
            f"{paketverzeichnis} lieferte fuer {dateiname} keine gueltige "
            f"UTF-8-Ausgabe ({fehler}). Aus dem Paketnamen werden Bezeichner, "
            "Urhebervermerk und Lizenztext gelesen -- ein Ersatzzeichen darin wuerde "
            "auf ein fremdes Paket und damit auf einen fremden Lizenztext fuehren."
        ) from fehler
    if ergebnis.returncode != 0:
        return None
    pakete: list[str] = []
    for zeile in ergebnis.stdout.splitlines():
        paketteil, trenner, _ = zeile.partition(": ")
        if not trenner:
            continue
        for stueck in paketteil.split(","):
            paket = stueck.strip().split(":", 1)[0]
            if paket and paket not in pakete:
                pakete.append(paket)
    # Mehrdeutigkeit ist kein Beleg: liefern mehrere Pakete denselben Dateinamen,
    # laesst sich nicht sagen, aus welchem die eingebettete Fassung stammt.
    return pakete[0] if len(pakete) == 1 else None


def _dep5_feld(absatz: str, feld: str) -> str | None:
    """Liest ein DEP-5-Feld WORTGETREU, samt eingerueckter Fortsetzungszeilen.

    Entfernt wird je Zeile GENAU EIN fuehrendes Leerzeichen -- das
    Fortsetzungszeichen, das DEP-5 jeder Folgezeile voranstellt. Jede weitere
    Einrueckung gehoert zum Wert und bleibt stehen: sie taefelt Aufzaehlungen,
    Jahreszahlen-Spalten und eingerueckte Absaetze. Sie zu entfernen waere ein
    Umbruch fremden Lizenztextes (Regel 3).

    Ist das erste Zeichen kein Leerzeichen (ein Tabulator, wie ihn etwa
    ``libssl3t64`` als Fortsetzungszeichen verwendet), bleibt die Zeile
    unangetastet -- dasselbe tut die Referenzimplementierung ``python3-debian``.

    Leere Zeilen entfallen; sie treten nur als Zeile direkt hinter ``Feld:``
    auf, wenn der Wert erst in der Folgezeile beginnt, und tragen keinen Inhalt.
    Die DEP-5-Leerzeile schreibt sich ``.`` und bleibt als solche erhalten.
    """
    treffer = re.search(DEP5_FELD_MUSTER.format(feld=feld), absatz, re.MULTILINE)
    if treffer is None:
        return None
    zeilen = [
        zeile[1:] if zeile.startswith(" ") else zeile
        for zeile in treffer.group("wert").splitlines()
    ]
    wert = "\n".join(zeile for zeile in zeilen if zeile)
    return wert or None


def lies_copyright_angaben(text: str) -> tuple[str | None, str | None]:
    """Liest Bezeichner und Urhebervermerk aus einer ``copyright``-Datei.

    Beides wird ausschliesslich den ausgewiesenen Feldern des maschinenlesbaren
    Formats (DEP-5) des Absatzes ``Files: *`` entnommen und WORTGETREU uebernommen.
    Eine Freitext-Fassung liefert hier nichts: dort ist ``License:`` Teil eines
    Fliesstextes und ``COPYRIGHT STATEMENTS AND LICENSING TERMS`` eine Ueberschrift.
    Beides als Angabe zu lesen waere eine Deutung, kein Beleg (Regel 2).
    """
    if DEP5_KOPF_MUSTER.search(text) is None:
        return None, None
    for absatz in re.split(r"\n[ \t]*\n", text):
        if DEP5_ALLE_DATEIEN_MUSTER.search(absatz) is None:
            continue
        return _dep5_feld(absatz, "License"), _dep5_feld(absatz, "Copyright")
    return None, None


def _binaries_im_verzeichnis(verzeichnis: Path) -> list[Path]:
    """Die PyInstaller-Binaries eines Verzeichnisses, nach Namen geordnet.

    Genommen wird jede ausfuehrbare Datei, die ein CArchive traegt. Eine
    ausfuehrbare Datei OHNE Archiv ist kein Fehler -- sie ist schlicht kein
    PyInstaller-Binary. Enthaelt das Verzeichnis gar keines, ist das ein Fehler:
    dann ist der Schalter falsch gesetzt, und eine leere Ebene ``nativ`` waere ein
    stiller Rueckfall.
    """
    if not verzeichnis.is_dir():
        raise SystemExit(f"--binaerverzeichnis: {verzeichnis} ist kein Verzeichnis")
    gefunden: list[Path] = []
    for pfad in sorted(verzeichnis.iterdir()):
        if not pfad.is_file() or not pfad.stat().st_mode & 0o111:
            continue
        with pfad.open("rb") as strom:
            if _finde_carchive_magie(strom) >= 0:
                gefunden.append(pfad)
    if not gefunden:
        raise SystemExit(f"--binaerverzeichnis: {verzeichnis} enthaelt kein PyInstaller-Binary")
    return gefunden


def sammle_nativ(
    sammler: Sammler,
    verzeichnis: Path,
    zielplattform: str,
    endungen: Sequence[str],
    paketverzeichnis: str | None,
) -> dict[str, Any]:
    """Erhebt die Ebene ``nativ`` aus den fertigen PyInstaller-Binaries.

    Fuer jede Bibliothek werden Dateiname und Groesse aus dem Archiv genommen. Das
    liefernde Systempaket kommt aus der Paketdatenbank DIESES Systems, Bezeichner
    und Urhebervermerk wortgetreu aus dessen ``copyright``-Datei, deren Volltext als
    Lizenztext gefuehrt wird. Bibliotheken aus dem Ordner eines Python-Rades
    (``pillow.libs/``) werden ihrem Python-Paket zugeordnet, statt sie doppelt zu
    fuehren.

    Fehlt der Zielplattform ein Paketverzeichnis, wird die Ebene ausdruecklich als
    "nicht ermittelbar" gefuehrt (dritter Zustand) statt als leere Erhebung. Das ist
    kein Fehler: die Quelle, aus der Systempaket und Lizenztext hervorgingen, gibt
    es dort schlicht nicht.
    """
    if paketverzeichnis is None:
        return {
            "erhoben": False,
            "zustand": NATIV_OHNE_PAKETVERZEICHNIS,
            "zielplattform": zielplattform,
            "hinweis": EBENE_NATIV_OHNE_PAKETVERZEICHNIS.format(plattform=zielplattform),
            "quelle_der_binaries": str(verzeichnis),
            "gelesene_binaries": [],
            "eintraege": [],
        }
    binaries = _binaries_im_verzeichnis(verzeichnis)
    # Dieselbe Bibliothek steckt in beiden Binaries. Sie wird EINMAL gefuehrt und
    # nennt, in welchen Binaries sie vorkommt.
    gefunden: dict[str, dict[str, Any]] = {}
    for binaer in binaries:
        for name, typ, groesse in lies_carchive_verzeichnis(binaer):
            if typ != CARCHIVE_TYP_BINAER or not ist_native_bibliothek(name, endungen):
                continue
            vorhanden = gefunden.get(name)
            if vorhanden is None:
                gefunden[name] = {
                    "archivname": name,
                    "dateiname": name.rsplit("/", 1)[-1],
                    "groesse_bytes": groesse,
                    "binaries": [binaer.name],
                }
            elif binaer.name not in vorhanden["binaries"]:
                vorhanden["binaries"].append(binaer.name)

    eintraege: list[dict[str, Any]] = []
    paketcache: dict[str, str | None] = {}
    for name in sorted(gefunden):
        angaben = gefunden[name]
        radtreffer = RAD_BIBLIOTHEKSORDNER_MUSTER.match(name)
        if radtreffer is not None:
            eintraege.append(_nativ_aus_python_rad(angaben, radtreffer.group("paket")))
            continue
        dateiname = str(angaben["dateiname"])
        if dateiname not in paketcache:
            paketcache[dateiname] = _paket_zu_datei(dateiname, paketverzeichnis)
        eintraege.append(_nativ_aus_systempaket(sammler, angaben, paketcache[dateiname]))

    # Bibliotheken gefunden UND eine Paketdatenbank vorhanden, aber kein einziger
    # Eintrag entstanden: das waere eine leere Erhebung trotz vorhandener Quelle --
    # genau der stille Rueckfall, den diese Ebene nicht kennen darf. Ein Fehler,
    # kein leiser Rueckfall auf eine leere Liste.
    if gefunden and not eintraege:
        raise SystemExit(
            f"Ebene nativ: in {verzeichnis} wurden {len(gefunden)} native Bibliotheken "
            f"gefunden und {paketverzeichnis} ist vorhanden, es entstand aber kein "
            "einziger Eintrag. Eine leere Erhebung bei vorhandener Quelle ist ein "
            "stiller Rueckfall und nicht zulaessig."
        )

    return {
        "erhoben": True,
        "zustand": NATIV_ERHOBEN,
        "zielplattform": zielplattform,
        "hinweis": (
            "Erhoben aus dem Inhaltsverzeichnis der fertigen PyInstaller-Binaries in "
            f"{verzeichnis}, rein lesend. Paket, Bezeichner und Urhebervermerk stammen "
            "aus der Paketdatenbank DIESES Systems -- im Bauimage koennen andere "
            "Fassungen und damit andere Angaben gelten."
        ),
        "quelle_der_binaries": str(verzeichnis),
        "gelesene_binaries": [binaer.name for binaer in binaries],
        "eintraege": eintraege,
    }


def _nativ_aus_python_rad(angaben: dict[str, Any], paket: str) -> dict[str, Any]:
    """Eine Bibliothek aus dem Ordner eines Python-Rades (Punkt 1f).

    Sie wird nicht doppelt gefuehrt: Bezeichner, Text und Vermerk stehen beim
    Python-Paket auf der Ebene ``python``. Hier steht nur der Verweis darauf.
    """
    return {
        "dateiname": str(angaben["dateiname"]),
        "archivname": str(angaben["archivname"]),
        "groesse_bytes": int(angaben["groesse_bytes"]),
        "binaries": list(angaben["binaries"]),
        "herkunft": "python_paket",
        "python_paket": paket,
        "lieferndes_paket": None,
        "lieferndes_paket_quelle": QUELLE_NICHT_BELEGT,
        "lizenz_id": None,
        "lizenz_id_quelle": QUELLE_NICHT_BELEGT,
        "urhebervermerk": None,
        "urhebervermerk_quelle": QUELLE_NICHT_BELEGT,
        "lizenz_text_ref": None,
        "lizenz_text_quelle": QUELLE_NICHT_BELEGT,
        "copyright_datei": None,
        "hinweis": (
            f"Vom Python-Paket {paket} mitgebracht. Bezeichner, Lizenztext und "
            f"Urhebervermerk sind auf der Ebene python beim Paket {paket} gefuehrt "
            "und werden hier nicht wiederholt."
        ),
    }


def _nativ_aus_systempaket(
    sammler: Sammler,
    angaben: dict[str, Any],
    paket: str | None,
) -> dict[str, Any]:
    """Eine Bibliothek aus einem Systempaket, belegt ueber dessen copyright-Datei."""
    eintrag: dict[str, Any] = {
        "dateiname": str(angaben["dateiname"]),
        "archivname": str(angaben["archivname"]),
        "groesse_bytes": int(angaben["groesse_bytes"]),
        "binaries": list(angaben["binaries"]),
        "herkunft": "systempaket",
        "python_paket": None,
        "lieferndes_paket": paket,
        "lieferndes_paket_quelle": QUELLE_SYSTEMPAKET if paket else QUELLE_NICHT_BELEGT,
        "lizenz_id": None,
        "lizenz_id_quelle": QUELLE_NICHT_BELEGT,
        "urhebervermerk": None,
        "urhebervermerk_quelle": QUELLE_NICHT_BELEGT,
        "lizenz_text_ref": None,
        "lizenz_text_quelle": QUELLE_NICHT_BELEGT,
        "copyright_datei": None,
    }
    if paket is None:
        # Kein Paket gefunden: nichts belegt, nichts genaehert (Regel 2).
        return eintrag

    datei = Path("/usr/share/doc") / paket / "copyright"
    text = lies_text(datei) if datei.is_file() else None
    if text is None:
        return eintrag

    eintrag["copyright_datei"] = str(datei)
    # Der Volltext dieser Datei IST der Lizenztext des Pakets -- Quelle paketdatei,
    # Fundstelle der Pfad, unter dem er gelesen wurde.
    schluessel, textquelle = sammler.text_aus_paketdatei(f"nativ/{paket}", datei, text)
    eintrag["lizenz_text_ref"] = schluessel
    eintrag["lizenz_text_quelle"] = textquelle

    bezeichner, vermerk = lies_copyright_angaben(text)
    if bezeichner is not None:
        eintrag["lizenz_id"] = bezeichner
        eintrag["lizenz_id_quelle"] = QUELLE_SYSTEMPAKET
    if vermerk is not None:
        eintrag["urhebervermerk"] = vermerk
        eintrag["urhebervermerk_quelle"] = QUELLE_SYSTEMPAKET
    return eintrag


# --------------------------------------------------------------------------------
# Werk und Zusammenbau
# --------------------------------------------------------------------------------


#: Die Orte, die die Lizenzangabe des EIGENEN Werks fuehren (Regel L). Je Ort der
#: Dateipfad relativ zur Wurzel und die ADRESSE des Feldes innerhalb der Datei --
#: eine Folge von Schluesseln, die von der Wurzel des Dokuments abwaerts gelesen
#: wird. Der leere Schluessel ``""`` ist echt: so heisst in den beiden Lock-Dateien
#: der Eintrag des eigenen Wurzelpakets.
#:
#: Die Liste ist gemessen, nicht geraten: sie fuehrt genau die sieben Stellen, an
#: denen heute ``GPL-2.0-only`` steht. Die beiden Lock-Dateien gehoeren dazu,
#: obwohl npm sie erzeugt: sie fuehren die Angabe eigenstaendig, und ein Lock, das
#: nach einer Aenderung der package.json nicht neu erzeugt wurde, traegt weiter den
#: alten Wert -- genau die stille Abweichung, gegen die dieser Waechter steht.
#:
#: NACHFUEHREN: kommt ein Manifest hinzu, das die Lizenz des Werks fuehrt, oder
#: faellt eines weg, ist diese Liste von Hand nachzuziehen.
WERK_LIZENZ_ORTE: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("pyproject.toml", ("project", "license")),
    ("package.json", ("license",)),
    ("frontend/package.json", ("license",)),
    ("package-lock.json", ("packages", "", "license")),
    ("frontend/package-lock.json", ("packages", "", "license")),
    ("src-tauri/Cargo.toml", ("package", "license")),
    ("src-tauri/tauri.conf.json", ("bundle", "license")),
)


def _werk_lizenz_an_ort(wurzel: Path, datei: str, adresse: Sequence[str]) -> str:
    """Liest die Lizenzangabe an EINEM Ort ueber ihre Adresse -- oder faellt.

    Der Waechter prueft ueber die ADRESSIERUNG, wie die bestehenden Ebenen-Waechter
    es tun: gesucht wird nicht irgendein Vorkommen der Zeichenkette in der Datei,
    sondern genau EIN Feld an genau EINER Stelle. Findet sich dort kein Wert oder
    ein Wert der falschen Art, faellt das Werkzeug mit eigener Meldung, statt den
    Ort zu ueberspringen. Ein uebergangener Ort waere eine ungeprueft
    durchgelassene Abweichung -- der stille Rueckfall, gegen den Regel L steht
    (Finding S3).

    Eine fehlende Datei faellt hier ebenso: die sieben Orte sind fest verdrahtet,
    weil sie erklaertermassen die Lizenz des Werks fuehren.
    """
    feldweg = ".".join(a if a else '""' for a in adresse)
    stelle = f"Werk-Lizenz, Ort {datei} (Feld {feldweg})"
    pfad = wurzel / datei
    if not pfad.is_file():
        raise SystemExit(
            f"{stelle}: die Datei ist unter {pfad} nicht vorhanden. Dieser Ort "
            "fuehrt die Lizenzangabe des eigenen Werks; ohne ihn laesst sich nicht "
            "pruefen, ob alle Orte dieselbe Angabe fuehren. Ein stillschweigend "
            "uebersprungener Ort waere ein stiller Rueckfall. Entweder fehlt die "
            "Datei im Arbeitsbaum, oder sie ist entfallen und gehoert aus "
            "WERK_LIZENZ_ORTE entfernt."
        )
    try:
        if datei.endswith(".toml"):
            with pfad.open("rb") as strom:
                dokument: Any = tomllib.load(strom)
        else:
            roh = lies_text(pfad)
            if roh is None:
                raise SystemExit(f"{stelle}: die Datei ist nicht lesbar.")
            dokument = json.loads(roh)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as fehler:
        raise SystemExit(f"{stelle}: die Datei ist nicht auswertbar ({fehler}).") from fehler

    # Die Adressierung selbst: genau EIN Kandidat muss herauskommen. Jeder Schritt
    # ins Leere ist ein Abbruch mit eigener Meldung, die den erreichten Weg nennt.
    knoten: Any = dokument
    for tiefe, schluessel in enumerate(adresse):
        if not isinstance(knoten, dict) or schluessel not in knoten:
            erreicht = ".".join(a if a else '""' for a in adresse[:tiefe]) or "<Dokumentwurzel>"
            fehlend = schluessel if schluessel else '""'
            raise SystemExit(
                f"{stelle}: an dieser Adresse steht kein Kandidat -- unter "
                f"{erreicht} gibt es den Schluessel {fehlend} nicht. "
                "Der Ort fuehrt die Lizenzangabe des Werks nicht mehr an der "
                "erwarteten Stelle. Entweder ist die Angabe entfallen, oder sie ist "
                "umgezogen und WERK_LIZENZ_ORTE gehoert nachgezogen. Geraten wird "
                "nichts."
            )
        knoten = knoten[schluessel]
    if not isinstance(knoten, str) or not knoten.strip():
        raise SystemExit(
            f"{stelle}: an dieser Adresse steht kein einzelner Lizenzbezeichner, "
            f"sondern {knoten!r}. Ein Waechter, der daraus einen Wert erriete, "
            "waere kein Beleg."
        )
    return knoten.strip()


def pruefe_werk_lizenz(wurzel: Path) -> str:
    """REGEL L: alle Orte des Werks fuehren DIESELBE Lizenzangabe -- oder Abbruch.

    Existenzforderung, nicht blosse Abfrage: jeder der sieben Orte MUSS vorhanden
    sein und dort MUSS eine Angabe stehen (das prueft :func:`_werk_lizenz_an_ort`).
    Gehen die Werte auseinander, faellt das Werkzeug -- keine Warnung, kein
    Weiterlaufen. Eine abweichende Angabe ist keine Kleinigkeit: sie besagt, dass
    das Werk unter zwei verschiedenen Bedingungen ausgeliefert wird, und welche
    davon gilt, entschiede dann der Zufall des Leseortes.

    Liefert die uebereinstimmende Angabe zurueck, damit der Aufrufer sie nicht ein
    zweites Mal von der Platte lesen muss.
    """
    gemessen = {
        datei: _werk_lizenz_an_ort(wurzel, datei, adresse) for datei, adresse in WERK_LIZENZ_ORTE
    }
    werte = sorted(set(gemessen.values()))
    if len(werte) != 1:
        aufstellung = "; ".join(f"{datei}: {wert!r}" for datei, wert in gemessen.items())
        raise SystemExit(
            f"Werk-Lizenz: die {len(WERK_LIZENZ_ORTE)} Orte der Lizenzangabe fuehren "
            f"{len(werte)} verschiedene Werte ({', '.join(repr(w) for w in werte)}). "
            f"Im Einzelnen -- {aufstellung}. Regel L fordert an allen Orten dieselbe "
            "Angabe: gehen sie auseinander, sagt die Auslieferung ueber ihre eigenen "
            "Bedingungen zweierlei, und welche Angabe gilt, entschiede der Zufall des "
            "Leseortes. Die abweichenden Orte sind auf den gueltigen Wert zu bringen."
        )
    return werte[0]


def lies_produktversion(wurzel: Path) -> str:
    with (wurzel / "pyproject.toml").open("rb") as strom:
        daten = tomllib.load(strom)
    version = daten.get("project", {}).get("version")
    if not isinstance(version, str):
        raise SystemExit("pyproject.toml fuehrt keine Version unter project.version")
    return version


def baue_werk(sammler: Sammler, wurzel: Path) -> dict[str, Any]:
    """Das eigene Werk. Der Lizenztext ist die Wurzel-LICENSE, nie die SPDX-Fassung.

    Der Bezeichner kommt aus :func:`pruefe_werk_lizenz` und damit erst, NACHDEM alle
    Orte der Regel L als uebereinstimmend belegt sind. Ihn hier aus der
    ``pyproject.toml`` allein zu lesen hiesse, einen von sieben Orten willkuerlich
    zum Massstab zu erheben, waehrend die uebrigen sechs ungeprueft blieben.
    """
    with (wurzel / "pyproject.toml").open("rb") as strom:
        daten = tomllib.load(strom)
    projekt = daten.get("project", {})
    bezeichner = pruefe_werk_lizenz(wurzel)
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

    bezug, bezug_quelle = _werk_quelltext_bezug(daten)
    return {
        "name": projekt.get("name"),
        "urheber": urheber,
        "lizenz_id": bezeichner,
        "lizenz_text": ref,
        "lizenz_text_quelle": quelle,
        "quelltext_bezug": bezug,
        "quelltext_bezug_quelle": bezug_quelle,
    }


def _werk_quelltext_bezug(daten: dict[str, Any]) -> tuple[str | None, str]:
    """Der Bezugsort des EIGENEN Quelltextes aus ``[tool.cernis_pro]``.

    EINZIGE Quelle der Angabe (siehe Kommentar in ``pyproject.toml``). Nicht zu
    verwechseln mit dem Feld ``projektadresse`` der Bestandteile: das nennt die
    Projektseite eines FREMDEN Bestandteils, dies hier den Bezug des eigenen Codes.

    Fehlt die Angabe oder ist sie leer, ist der Wert ``None`` und die Quelle
    ``nicht_belegt`` -- niemals ein geratener Link, niemals eine Adresse aus dem
    git-remote und kein Ersatztext (Finding S3: kein stiller Rueckfall).
    """
    wert = daten.get("tool", {}).get("cernis_pro", {}).get("quelltext_bezug")
    if not isinstance(wert, str) or not wert.strip():
        return None, QUELLE_NICHT_BELEGT
    return wert.strip(), QUELLE_PROJEKTKONFIGURATION


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
    nativ_eintraege = ergebnis["ebene_nativ"]["eintraege"]
    verweise = [
        eintrag["lizenz_text_ref"]
        for eintrag in [*ergebnis["bestandteile"], *nativ_eintraege]
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
    pruefe_ebene_leere(ergebnis["bestandteile"])
    pruefe_ebene_nativ(nativ_eintraege)


#: Die Ebenen der Bestandteile, die NICHT leer sein duerfen. Gemessen, nicht
#: gesetzt: keine der fuenf kann legitim leer sein, und zwar aus je eigenem Grund.
#:
#: ``daten`` und ``programme`` laufen ueber die von Hand gefuehrten Listen
#: ``DATENBESTAENDE`` und ``FREMDPROGRAMME``; beide sind fest verdrahtet und im
#: Werkzeug selbst gefuellt -- leer koennen sie nur werden, wenn jemand die Liste
#: leert. ``python``, ``npm`` und ``rust`` laufen ueber eine Erhebung, deren
#: Massstab (uv-Lock, package.json, Cargo-Metadaten) jeweils erklaertermassen
#: Bestandteile nennt; ist die Erhebung leer, ist sie ausgefallen.
#:
#: Kein Gegenstueck zur Ebene ``nativ``: DIE darf leer sein und erklaert das
#: ausdruecklich ueber ihr Feld ``zustand``. Genau diese Erklaerung fehlt den fuenf
#: hier -- sie haben kein Feld, in dem eine zulaessige Leere stuende, und deshalb
#: ist ihre Leere ein Abbruch. Kaeme je eine Ebene hinzu, die legitim leer sein
#: kann, gehoerte sie NICHT hierher, sondern brauchte einen ``zustand`` nach dem
#: Vorbild von ``nativ``.
PFLICHTEBENEN: Final[tuple[str, ...]] = ("daten", "npm", "programme", "python", "rust")


def pruefe_ebene_leere(bestandteile: Sequence[dict[str, Any]]) -> None:
    """Prueft JEDE Pflichtebene darauf, dass sie Eintraege fuehrt.

    Die abschliessende Ergebnispruefung sah bisher keine Ebene auf Leere durch:
    verschwand eine still, meldete der Lauf Erfolg. Die Ebenen-Waechter der
    Sammelstellen greifen frueher, aber jeder nur fuer seine eigene Ebene und nur
    dort, wo er sitzt -- diese Pruefung steht am Ende ueber ALLEN und faengt auch
    den Fall, dass eine Ebene aus ``erzeuge`` herausfaellt und ihr Waechter damit
    gar nicht erst laeuft.

    Die Meldung nennt die betroffene Ebene NAMENTLICH, nicht bloss eine Zahl: eine
    fehlende Zahl sagt nicht, wonach zu suchen ist.
    """
    gezaehlt: dict[str, int] = {}
    for eintrag in bestandteile:
        ebene = str(eintrag["ebene"])
        gezaehlt[ebene] = gezaehlt.get(ebene, 0) + 1
    leer = [ebene for ebene in PFLICHTEBENEN if not gezaehlt.get(ebene)]
    if leer:
        bestand = ", ".join(f"{e}: {gezaehlt.get(e, 0)}" for e in PFLICHTEBENEN)
        raise SystemExit(
            f"Leere Ebene(n) in der Aufstellung: {', '.join(leer)}. Bestand je "
            f"Pflichtebene -- {bestand}. Keine dieser Ebenen darf leer sein: anders "
            "als die Ebene nativ, die eine zulaessige Leere ueber ihr Feld zustand "
            "erklaert, fuehren sie kein Feld, in dem eine leere Ebene als solche "
            "ausgewiesen waere. Eine still verschwundene Ebene liefe sonst als "
            "Erfolg durch, und die Aufstellung behauptete eine Vollstaendigkeit, "
            "die sie nicht hat."
        )


def pruefe_ebene_nativ(eintraege: Sequence[dict[str, Any]]) -> None:
    """Prueft die Zusagen der Ebene ``nativ``, allen voran Regel 2.

    Ein leeres Feld muss die Quelle ``nicht_belegt`` tragen, ein belegtes Feld eine
    zulaessige Quelle. Der Lizenztext darf nur aus der gelesenen ``copyright``-Datei
    stammen -- eine andere Quelle waere ein Ersatztext.
    """
    for eintrag in eintraege:
        name = eintrag["dateiname"]
        felder = ("lieferndes_paket", "lizenz_id", "urhebervermerk", "lizenz_text_ref")
        for feld in felder:
            quelle = eintrag[f"{feld.removesuffix('_ref')}_quelle"]
            if quelle not in ZULAESSIGE_QUELLEN:
                raise SystemExit(f"{name}: unzulaessige Quelle {quelle!r} fuer {feld}")
            if eintrag[feld] is None and quelle != QUELLE_NICHT_BELEGT:
                raise SystemExit(f"{name}: {feld} ist leer, Quelle aber {quelle!r}")
            if eintrag[feld] is not None and quelle == QUELLE_NICHT_BELEGT:
                raise SystemExit(f"{name}: {feld} ist belegt, Quelle aber nicht_belegt")
            if eintrag[feld] == "":
                raise SystemExit(f"{name}: {feld} ist ein leerer String")
        if eintrag["lizenz_text_ref"] is not None:
            if eintrag["lizenz_text_quelle"] != QUELLE_PAKETDATEI:
                raise SystemExit(
                    f"{name}: Lizenztext stammt aus {eintrag['lizenz_text_quelle']!r} "
                    "statt aus der gelesenen copyright-Datei"
                )
            if not eintrag["copyright_datei"]:
                raise SystemExit(f"{name}: Lizenztext ohne benannte Fundstelle")


def erzeuge(
    wurzel: Path,
    binaerverzeichnis: Path | None = None,
    zielplattform: str = ZIELPLATTFORM_VORGABE,
) -> dict[str, Any]:
    merkmale = ZIELPLATTFORMEN[zielplattform]
    sammler = Sammler(wurzel)
    sammle_python(sammler, wurzel)
    sammle_npm(sammler, wurzel)
    sammle_rust(sammler, wurzel, str(merkmale["rust_ziel"]))
    sammle_daten(sammler, wurzel)
    sammle_programme(sammler)

    if binaerverzeichnis is None:
        ebene_nativ: dict[str, Any] = {
            "erhoben": False,
            "zustand": NATIV_NICHT_ANGEFORDERT,
            "zielplattform": zielplattform,
            "hinweis": EBENE_NATIV_HINWEIS,
            "quelle_der_binaries": None,
            "gelesene_binaries": [],
            "eintraege": [],
        }
    else:
        ebene_nativ = sammle_nativ(
            sammler,
            binaerverzeichnis,
            zielplattform,
            tuple(merkmale["bibliotheksendungen"]),
            merkmale["paketverzeichnis"],
        )

    ergebnis: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "erzeugt_am": datetime.now(UTC).isoformat(timespec="seconds"),
        "produktversion": lies_produktversion(wurzel),
        "plattform": zielplattform,
        "werk": baue_werk(sammler, wurzel),
        "bestandteile": sammler.bestandteile,
        "lizenztexte": sammler.lizenztexte,
        "luecken": sammle_luecken(sammler.bestandteile),
        "ebene_nativ": ebene_nativ,
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
    zerleger.add_argument(
        "--binaerverzeichnis",
        type=Path,
        default=None,
        help=(
            "Verzeichnis mit den fertigen PyInstaller-Binaries. Nur mit diesem "
            "Schalter wird die Ebene nativ erhoben; ohne ihn bleibt sie "
            "erhoben=false."
        ),
    )
    zerleger.add_argument(
        "--zielplattform",
        choices=sorted(ZIELPLATTFORMEN),
        default=ZIELPLATTFORM_VORGABE,
        help=(
            "Plattform, FUER die gebaut wird -- nicht die, auf der dieses Werkzeug "
            "laeuft. Daraus folgen das Rust-Ziel und die Endungen der nativen "
            f"Bibliotheken. Vorgabe: {ZIELPLATTFORM_VORGABE}."
        ),
    )
    argumente = zerleger.parse_args(argv)

    wurzel = argumente.wurzel.resolve()
    binaerverzeichnis = (
        argumente.binaerverzeichnis.resolve() if argumente.binaerverzeichnis is not None else None
    )
    ergebnis = erzeuge(wurzel, binaerverzeichnis, argumente.zielplattform)
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

    nativ = ergebnis["ebene_nativ"]
    if nativ["zustand"] == NATIV_NICHT_ANGEFORDERT:
        print("  Ebene nativ: nicht angefordert (kein --binaerverzeichnis)")
        return 0
    if nativ["zustand"] == NATIV_OHNE_PAKETVERZEICHNIS:
        print(
            f"  Ebene nativ: angefordert, auf {nativ['zielplattform']} nicht "
            "ermittelbar (kein Paketverzeichnis)"
        )
        return 0
    eintraege = nativ["eintraege"]
    aus_rad = [e for e in eintraege if e["herkunft"] == "python_paket"]
    aus_paket = [e for e in eintraege if e["herkunft"] == "systempaket"]
    zugeordnet = [e for e in aus_paket if e["lieferndes_paket"] is not None]
    mit_datei = [e for e in aus_paket if e["copyright_datei"] is not None]
    unbelegt = [e for e in aus_paket if e["lizenz_text_ref"] is None]
    print(f"  Ebene nativ            {len(eintraege):>4} Bibliotheken")
    print(f"    davon aus Python-Paket {len(aus_rad):>4}")
    print(f"    davon aus Systempaket  {len(aus_paket):>4}")
    print(f"    Paket zugeordnet       {len(zugeordnet):>4}")
    print(f"    copyright gelesen      {len(mit_datei):>4}")
    print(f"    nicht_belegt           {len(unbelegt):>4}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
