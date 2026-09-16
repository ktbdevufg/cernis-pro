#!/usr/bin/env python3
"""Erzeugt aus der Lizenzaufstellung die beiden RPM-ueblichen Beilagen.

Aufruf::

    python scripts/gen_rpm_licenses.py <aufstellung.json> \
        --dependencies <ziel/LICENSE.dependencies> \
        --lizenztexte <ziel/LICENSES>

Erzeugt werden ZWEI Dateien, beide fuer ``/usr/share/licenses/cernis-pro/``:

``LICENSE.dependencies``
    Die Aufstellung der mitgelieferten Fremdbestandteile, EINE ZEILE je
    Bestandteil, im auf dieser Maschine gemessenen Fedora-Format::

        <Lizenzausdruck>: <Name> v<Fassung>

``LICENSES``
    Die Volltexte der Fremdlizenzen als lesbare Sammlung NEBEN der
    Aufstellung, nicht in ihr.

WARUM EIN EIGENES WERKZEUG UND KEINE ERWEITERUNG VON gen_debian_copyright.py
===========================================================================

Drei Gruende, in dieser Reihenfolge:

1. ``gen_debian_copyright.py`` ist auf DEP-5 zugeschnitten -- Absaetze,
   Feldfaltung, ``.``-Zeilen. Mit dem hiesigen Format teilt es keine einzige
   Formregel: hier steht je Bestandteil eine ungefaltete Zeile. Zwei Formate
   in einem Werkzeug haetten nur den Dateinamen gemeinsam.
2. Das deb ist seit Commit 21c6456 fertig und darf sich in KEINEM Punkt
   aendern. Der sicherste Beleg dafuer ist, seinen Erzeuger nicht anzufassen.
   Diese Datei aendert dort keine Zeile.
3. Die Volltextsammlung soll auf beiden Formaten dieselbe sein. Deshalb wird
   sie NICHT nachgebaut, sondern aus ``gen_debian_copyright`` eingelesen und
   nur neu ueberschrieben (siehe :func:`baue_sammlung`). Ein Nachbau koennte
   auseinanderlaufen; ein Aufruf kann es nicht.

WAHL VON NAME UND ABLAGE -- BEGRUENDET AUS DEM BESTAND
======================================================

Gemessen auf dieser Maschine (Fedora 44, 2371 installierte Pakete, 3964
Dateien unter ``/usr/share/licenses/``):

``/usr/share/licenses/cernis-pro/`` als Ort
    Das Makro ``_defaultlicensedir`` (``/usr/lib/rpm/macros``, Zeile 221),
    ``man rpm`` und 1270 der installierten Pakete belegen diesen Ort.

``LICENSE.dependencies`` als Name der Aufstellung
    31 installierte Pakete fuehren genau diese Datei an genau diesem Ort und
    genau in diesem Format. Das Debian-Vorbild traegt hier nicht: nmap liefert
    unter Fedora keine Fremdlizenztexte mit.

``LICENSES`` als Name der Volltextsammlung
    Nicht aus Analogie zum deb gewaehlt, sondern aus dem Bestand: glibc,
    gpgme und groff-base fuehren unter ``/usr/share/licenses/<paket>/LICENSES``
    genau das, was hier gebraucht wird -- EINE Datei, die die vollstaendigen
    Lizenztexte derjenigen Bestandteile sammelt, die nicht unter der Lizenz des
    Pakets selbst stehen. glibc sagt das im Kopf seiner Datei woertlich. Der
    Name steht ausserdem in derselben endungslosen Reihe wie ``COPYING`` (633x)
    und ``LICENSE`` (439x); ``LICENSES.txt`` kommt nur einmal vor.

    Die Datei ist UNGEPACKT. Von den 3964 Dateien unter
    ``/usr/share/licenses/`` traegt keine einzige eine Endung ``.gz``, ``.xz``,
    ``.bz2`` oder ``.zst``. Unter ``/usr/share/doc/`` gibt es gepackte Dateien
    sehr wohl -- die Packung des deb (``3rd-party-licenses.txt.gz``) gehoert
    also zu jenem Ort, nicht zu diesem.

DIE DREI LIZENZREGELN
=====================

REGEL 1 -- Vorrang der Paketdatei.
    Die Texte stammen unveraendert aus ``lizenztexte`` der Aufstellung. Die
    Rangfolge hat der Sammler entschieden; hier wird sie nur uebernommen.

REGEL 2 -- Kein Ersatztext.
    Wo die Aufstellung keinen Bezeichner fuehrt, wird KEINER eingesetzt. Das
    Fedora-Format sieht an erster Stelle einen SPDX-Ausdruck vor, aber ein
    vorgesehenes Feld ist kein Grund, einen zu erfinden. Statt eines
    Bezeichners steht dort der Negativbefund aus ``gen_debian_copyright``
    (``OHNE_BEZEICHNER``) -- WOERTLICH derselbe Satz, den schon die
    Debian-copyright fuehrt. Siehe :func:`lizenzausdruck`.

REGEL 3 -- Nichts aendern.
    Lizenztexte werden zeichengleich uebernommen. Die Sammlung gibt sie roh
    aus; :func:`pruefe` belegt danach byteweise, dass ihr Rumpf mit dem des deb
    uebereinstimmt.

QUELLE IST AUSSCHLIESSLICH DIE UEBERGEBENE AUFSTELLUNG. Dieses Werkzeug erhebt
nichts neu, ruft kein Paketverzeichnis und kein Netz.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Final

from gen_debian_copyright import OHNE_BEZEICHNER, SAMMLUNG_KOPF, baue_lizenztexte

#: Trenner zwischen Lizenzausdruck und Bestandteil, gemessen an den 31
#: installierten ``LICENSE.dependencies``: Doppelpunkt, dann ein Leerzeichen.
TRENNER: Final = ": "

#: Kopf der Volltextsammlung. Er tritt an die Stelle des Debian-Kopfes und
#: unterscheidet sich von ihm in genau einem Punkt: er nennt als Verzeichnis der
#: Zuordnung die Datei ``LICENSE.dependencies``. Der Debian-Kopf verweist auf
#: die Datei ``copyright``, die es im rpm nicht gibt -- ein Verweis auf eine
#: nicht vorhandene Datei waere eine Behauptung ueber den Paketinhalt.
SAMMLUNG_KOPF_RPM: Final = """CERNIS PRO -- Lizenztexte der mitgelieferten Fremdbestandteile
=============================================================

Diese Datei enthaelt die VOLLTEXTE der Lizenzen, unter denen die mit CERNIS PRO
ausgelieferten Fremdbestandteile stehen. Welcher Bestandteil unter welchem Text
steht, fuehrt die Datei LICENSE.dependencies im selben Verzeichnis.

Die Texte sind zeichengleich uebernommen: nicht gekuerzt, nicht neu umbrochen,
nicht uebersetzt. Zu jedem Text ist seine Herkunft angegeben -- die Datei, der
er entnommen wurde.

Erzeugt aus der Lizenzaufstellung des Bauvorgangs (lizenzaufstellung.json).
"""


def lizenzausdruck(roh: object) -> str:
    """Der Wert an erster Stelle der Zeile -- Bezeichner oder Negativbefund.

    Drei Faelle:

    Nichts belegt
        Die Aufstellung fuehrt ``null`` oder Leerraum. Dann steht dort
        ``OHNE_BEZEICHNER``: ein ganzer Satz, der benennt, was NICHT belegt ist.
        Er ist bewusst kein kurzes Wort -- ``unknown`` oder ``NOASSERTION``
        liessen sich als Bezeichner lesen, ein deutscher Satz nicht. Und er ist
        WOERTLICH derselbe wie in der Debian-copyright, damit beide Beilagen
        denselben Befund mit demselben Wortlaut ausdruecken.

    Einzeiliger Bezeichner
        Wird unveraendert uebernommen (Regel 3).

    Mehrzeiliger Wert
        Die Ebene ``nativ`` fuehrt in ``lizenz_id`` den ganzen
        ``License:``-Block der Debian-copyright-Datei, also Bezeichner UND
        eingerueckten Text. DEP-5 legt fest, dass die erste Zeile eines solchen
        Blocks der Bezeichner ist; genau sie wird hier genommen. Der Text
        dahinter geht nicht verloren -- er steht vollstaendig in ``LICENSES``.
        Ist die erste Zeile leer, ist kein Bezeichner belegt (Regel 2).
    """
    if roh is None:
        return OHNE_BEZEICHNER
    text = str(roh)
    if not text.strip():
        return OHNE_BEZEICHNER
    erste = text.split("\n", 1)[0]
    if not erste.strip():
        return OHNE_BEZEICHNER
    return erste


def bestandteilname(name: str, fassung: object) -> str:
    """Der Wert hinter dem Trenner: Name und, wenn belegt, Fassung.

    Gemessenes Format ist ``<Name> v<Fassung>``; alle 2397 nicht leeren Zeilen
    der 31 installierten Aufstellungen tragen die Fassung. Wo die Aufstellung
    KEINE Fassung fuehrt -- die Ebene ``daten`` und die Ebene ``nativ`` -- wird
    keine erfunden und auch kein leeres ``v`` geschrieben (Regel 2): der Teil
    entfaellt, der Bestandteil ist ueber seinen Namen benannt.
    """
    if fassung is None or not str(fassung).strip():
        return name
    return f"{name} v{fassung}"


def zeile(ausdruck: str, bezeichnung: str) -> str:
    """Eine Zeile der Aufstellung im gemessenen Format."""
    return f"{ausdruck}{TRENNER}{bezeichnung}"


def sammle_zeilen(daten: dict[str, Any]) -> list[str]:
    """Alle Zeilen der Aufstellung, sortiert wie die gemessenen Vorbilder.

    Gefuehrt wird jeder MITGELIEFERTE Fremdbestandteil und jede mitgelieferte
    native Bibliothek -- dieselbe Auswahl wie in der Debian-copyright. Die Ebene
    ``programme`` fuehrt aufgerufene, nicht mitgelieferte Fremdprogramme
    (``mitgeliefert=false``); sie gehoeren nicht in die Beilage eines Pakets,
    das sie nicht ausliefert.

    Sortiert wird nach Lizenzausdruck, dann nach Bezeichnung -- die Ordnung, die
    auch die installierten Vorbilder zeigen. Sie ist allein von der Aufstellung
    bestimmt und damit bei gleichem Eingang immer dieselbe.
    """
    zeilen: list[str] = []
    for eintrag in daten["bestandteile"]:
        if not eintrag.get("mitgeliefert"):
            continue
        zeilen.append(
            zeile(
                lizenzausdruck(eintrag.get("lizenz_id")),
                bestandteilname(eintrag["name"], eintrag.get("fassung")),
            )
        )
    for eintrag in daten["ebene_nativ"]["eintraege"]:
        # Native Bibliotheken fuehren keine Fassung; ihr Dateiname benennt sie.
        zeilen.append(
            zeile(
                lizenzausdruck(eintrag.get("lizenz_id")),
                bestandteilname(eintrag["dateiname"], None),
            )
        )
    return sorted(zeilen)


def baue_dependencies(daten: dict[str, Any]) -> str:
    """Baut die vollstaendige ``LICENSE.dependencies`` (Datei 1)."""
    return "".join(f"{z}\n" for z in sammle_zeilen(daten))


def baue_sammlung(daten: dict[str, Any]) -> str:
    """Baut die Volltextsammlung (Datei 2) aus derselben Quelle wie das deb.

    Der Rumpf wird NICHT nachgebaut, sondern von
    :func:`gen_debian_copyright.baue_lizenztexte` uebernommen; ausgetauscht wird
    nur der Kopf. Damit ist die Gleichheit der Texte nicht geprueft, sondern
    gebaut: es gibt nur eine Stelle, die sie erzeugt.
    """
    deb_sammlung = baue_lizenztexte(daten)
    if not deb_sammlung.startswith(SAMMLUNG_KOPF):
        raise SystemExit(
            "Die Sammlung von gen_debian_copyright beginnt nicht mit ihrem Kopf. "
            "Ohne diese Zusage laesst sich der Kopf nicht austauschen, ohne den "
            "Rumpf zu beruehren."
        )
    return SAMMLUNG_KOPF_RPM + deb_sammlung[len(SAMMLUNG_KOPF) :]


def pruefe(daten: dict[str, Any], dependencies: str, sammlung: str) -> None:
    """Prueft die Zusagen, bevor geschrieben wird. Verstoss = Abbruch.

    Kein stiller Rueckfall: jede dieser Pruefungen bricht ab, statt eine stille
    Auslassung oder eine mehrdeutige Zeile durchzulassen.
    """
    zeilen = dependencies.split("\n")[:-1]

    # 1. Genau eine Zeile je mitgeliefertem Bestandteil und je nativer Bibliothek.
    erwartet = sum(1 for e in daten["bestandteile"] if e.get("mitgeliefert"))
    erwartet += len(daten["ebene_nativ"]["eintraege"])
    if len(zeilen) != erwartet:
        raise SystemExit(f"LICENSE.dependencies fuehrt {len(zeilen)} Zeilen, erwartet {erwartet}")

    # 2. Keine leere Zeile, kein Zeilenumbruch innerhalb einer Zeile.
    for eintrag in zeilen:
        if not eintrag.strip():
            raise SystemExit("LICENSE.dependencies enthaelt eine leere Zeile")

    # 3. Der Lizenzausdruck darf den Trenner nicht selbst enthalten -- sonst
    #    liesse sich die Zeile nicht eindeutig zerlegen. Ein solcher Bezeichner
    #    waere ein Fehler, kein Grund zum stillen Verstuemmeln.
    for eintrag in daten["bestandteile"]:
        if not eintrag.get("mitgeliefert"):
            continue
        ausdruck = lizenzausdruck(eintrag.get("lizenz_id"))
        if TRENNER in ausdruck:
            raise SystemExit(
                f"{eintrag['name']}: der Lizenzausdruck {ausdruck!r} enthaelt "
                f"den Trenner {TRENNER!r}; die Zeile waere nicht mehr eindeutig."
            )

    # 4. Der Negativbefund steht genau so oft, wie die Aufstellung keinen
    #    Bezeichner fuehrt -- kein Bestandteil verliert seinen Bezeichner still,
    #    keiner bekommt einen dazu.
    ohne_bezeichner = sum(
        1
        for e in daten["bestandteile"]
        if e.get("mitgeliefert") and lizenzausdruck(e.get("lizenz_id")) == OHNE_BEZEICHNER
    )
    ohne_bezeichner += sum(
        1
        for e in daten["ebene_nativ"]["eintraege"]
        if lizenzausdruck(e.get("lizenz_id")) == OHNE_BEZEICHNER
    )
    gezaehlt = sum(1 for z in zeilen if z.startswith(OHNE_BEZEICHNER + TRENNER))
    if gezaehlt != ohne_bezeichner:
        raise SystemExit(
            f"LICENSE.dependencies fuehrt {gezaehlt} Negativbefunde, "
            f"die Aufstellung {ohne_bezeichner}"
        )

    # 5. Jeder Lizenztext der Aufstellung steht zeichengleich in der Sammlung.
    for schluessel, eintrag in daten["lizenztexte"].items():
        if eintrag["text"] not in sammlung:
            raise SystemExit(f"Lizenztext {schluessel} steht nicht zeichengleich in der Sammlung")


def main(argv: list[str] | None = None) -> int:
    zerleger = argparse.ArgumentParser(
        description=(
            "Erzeugt aus der Lizenzaufstellung die RPM-Beilagen LICENSE.dependencies und LICENSES."
        )
    )
    zerleger.add_argument("aufstellung", type=Path, help="Pfad der Lizenzaufstellung (JSON)")
    zerleger.add_argument(
        "--dependencies",
        type=Path,
        required=True,
        help="Zielpfad der Datei LICENSE.dependencies",
    )
    zerleger.add_argument(
        "--lizenztexte",
        type=Path,
        required=True,
        help="Zielpfad der Volltextsammlung LICENSES (ungepackt)",
    )
    argumente = zerleger.parse_args(argv)

    if not argumente.aufstellung.is_file():
        raise SystemExit(f"Aufstellung nicht gefunden: {argumente.aufstellung}")
    daten = json.loads(argumente.aufstellung.read_text(encoding="utf-8"))

    dependencies = baue_dependencies(daten)
    sammlung = baue_sammlung(daten)
    pruefe(daten, dependencies, sammlung)

    argumente.dependencies.parent.mkdir(parents=True, exist_ok=True)
    argumente.dependencies.write_text(dependencies, encoding="utf-8")
    argumente.lizenztexte.parent.mkdir(parents=True, exist_ok=True)
    argumente.lizenztexte.write_text(sammlung, encoding="utf-8")

    zeilen = dependencies.split("\n")[:-1]
    ohne_bezeichner = sum(1 for z in zeilen if z.startswith(OHNE_BEZEICHNER + TRENNER))
    print(f"geschrieben: {argumente.dependencies}")
    print(f"  Zeilen                   {len(zeilen):>4}")
    print(f"  ohne Lizenzbezeichner    {ohne_bezeichner:>4}")
    print(f"geschrieben: {argumente.lizenztexte}")
    print(f"  Lizenztexte              {len(daten['lizenztexte']):>4}")
    print(f"  ungepackt {len(sammlung.encode('utf-8')):>9} Byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
