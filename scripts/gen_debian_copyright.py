#!/usr/bin/env python3
"""Erzeugt aus der Lizenzaufstellung die beiden Debian-ueblichen Beilagen.

Aufruf::

    python scripts/gen_debian_copyright.py <aufstellung.json> \
        --copyright <ziel/copyright> \
        --lizenztexte <ziel/3rd-party-licenses.txt.gz>

Erzeugt werden ZWEI Dateien:

``copyright``
    Im maschinenlesbaren Format DEP-5 (Debian Policy, ``copyright-format/1.0``).
    Sie fuehrt das eigene Werk und jeden MITGELIEFERTEN Fremdbestandteil in je
    einem ``Files``-Absatz mit ``Copyright`` und ``License``.

``3rd-party-licenses.txt.gz``
    Die Volltexte der Fremdlizenzen als lesbare Sammlung NEBEN der copyright,
    nicht in ihr. Vorbild ist ``/usr/share/doc/nmap/3rd-party-licenses.txt.gz``.

QUELLE IST AUSSCHLIESSLICH DIE UEBERGEBENE AUFSTELLUNG. Dieses Werkzeug erhebt
nichts neu, ruft kein Paketverzeichnis und kein Netz. Was die Aufstellung nicht
fuehrt, fuehrt auch die copyright nicht.

DIE DREI LIZENZREGELN
=====================

REGEL 1 -- Vorrang der Paketdatei.
    Die Texte stammen unveraendert aus ``lizenztexte`` der Aufstellung. Deren
    Rangfolge (Paketdatei vor Ablage) hat bereits der Sammler entschieden; hier
    wird sie nur uebernommen, nie neu bewertet.

REGEL 2 -- Kein Ersatztext.
    Wo die Aufstellung ``null`` fuehrt, wird NICHTS eingesetzt -- kein
    Platzhalter, kein generischer Text, keine Vermutung. Das DEP-5-Format sieht
    fuer ``Copyright`` und ``License`` Pflichtfelder vor; ein vorgesehenes Feld
    ist aber kein Grund, eine Angabe zu erfinden. Stattdessen traegt das Feld
    einen ausdruecklichen Negativbefund (siehe ``OHNE_VERMERK`` /
    ``OHNE_BEZEICHNER``), der beschreibt, was NICHT belegt ist, statt etwas zu
    behaupten. Er ist als solcher erkennbar und nicht mit einem Bezeichner
    verwechselbar.

REGEL 3 -- Nichts aendern.
    Lizenztexte werden zeichengleich uebernommen: keine Kuerzung, kein
    Neuumbruch, keine Uebersetzung. Datei 2 gibt sie roh aus. In der copyright
    erzwingt DEP-5 eine Einrueckung um genau ein Leerzeichen und ``.`` fuer die
    Leerzeile; diese Faltung ist umkehrbar und veraendert den Text nicht --
    siehe :func:`falte_dep5`.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Any, Final

#: Der Formatzeiger des maschinenlesbaren Debian-copyright-Formats.
DEP5_FORMAT: Final = "https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"

#: Die Quellenkennung der Aufstellung fuer "nicht belegt".
NICHT_BELEGT: Final = "nicht_belegt"

#: Negativbefunde nach Regel 2. Sie behaupten nichts, sondern benennen genau,
#: was die Aufstellung NICHT fuehrt. Bewusst als ganzer Satz formuliert: ein
#: kurzes Wort wie "unknown" liesse sich als Lizenzbezeichner missdeuten, und
#: DEP-5 kennt keinen ausgewiesenen Wert fuer "nicht belegt".
OHNE_VERMERK: Final = (
    "Kein Urhebervermerk belegt. Die Aufstellung fuehrt zu diesem Bestandteil "
    "keinen Urhebervermerk; es wird keiner angenommen."
)
OHNE_BEZEICHNER: Final = (
    "Kein Lizenzbezeichner belegt. Die Aufstellung fuehrt zu diesem Bestandteil "
    "keinen Bezeichner; es wird keiner angenommen."
)

#: Ueberschrift der Sammlung in Datei 2.
SAMMLUNG_KOPF: Final = """CERNIS PRO -- Lizenztexte der mitgelieferten Fremdbestandteile
=============================================================

Diese Datei enthaelt die VOLLTEXTE der Lizenzen, unter denen die mit CERNIS PRO
ausgelieferten Fremdbestandteile stehen. Welcher Bestandteil unter welchem Text
steht, fuehrt die Datei copyright im selben Verzeichnis.

Die Texte sind zeichengleich uebernommen: nicht gekuerzt, nicht neu umbrochen,
nicht uebersetzt. Zu jedem Text ist seine Herkunft angegeben -- die Datei, der
er entnommen wurde.

Erzeugt aus der Lizenzaufstellung des Bauvorgangs (lizenzaufstellung.json).
"""


def falte_dep5(text: str) -> list[str]:
    """Faltet einen mehrzeiligen Wert in die DEP-5-Fortsetzungsform.

    DEP-5 verlangt fuer Folgezeilen genau ein fuehrendes Leerzeichen; eine
    Leerzeile wird als Zeile mit einem einzelnen ``.`` geschrieben, weil eine
    echte Leerzeile den Absatz beenden wuerde.

    Die Faltung ist umkehrbar und damit KEINE Aenderung im Sinne von Regel 3:
    Ein Leser entfernt je Zeile das erste Leerzeichen und ersetzt eine Zeile aus
    genau einem Punkt durch die Leerzeile -- und erhaelt den Ausgangstext
    zeichengleich zurueck.

    Eine Zeile, die selbst nur aus ``.`` besteht, wird zu ``. .`` -- sonst
    liesse sie sich beim Zuruecklesen nicht von einer gefalteten Leerzeile
    unterscheiden. Auch das ist umkehrbar.
    """
    zeilen: list[str] = []
    for rohzeile in text.split("\n"):
        zeile = rohzeile.rstrip("\r")
        if not zeile.strip():
            zeilen.append(" .")
        elif zeile.strip() == ".":
            zeilen.append(" . .")
        else:
            zeilen.append(" " + zeile)
    return zeilen


def einruecken_dep5(text: str) -> list[str]:
    """Rueckt einen bereits DEP-5-kodierten Wert nur wieder ein.

    Gegenstueck zu :func:`falte_dep5` fuer Werte, die die Aufstellung SCHON in
    DEP-5-Kodierung fuehrt: die Ebene ``nativ`` uebernimmt den ``License:``-Block
    der Debian-copyright-Datei, indem sie je Zeile das eine fuehrende Leerzeichen
    abstreift. Die Punktzeilen der Leerabsaetze bleiben dabei als ``.`` stehen
    (gemessen: libbz2 fuehrt 5 solcher Zeilen und keine einzige echte Leerzeile).

    Ein solcher Wert darf NICHT noch einmal gefaltet werden -- aus ``.`` wuerde
    ``. .``, und der Text waere veraendert (Regel 3). Hier wird deshalb nur das
    abgestreifte Leerzeichen zurueckgegeben, sonst nichts.
    """
    return [(" " + zeile) if zeile else " ." for zeile in text.split("\n")]


def feld(name: str, wert: str, schon_kodiert: bool = False) -> list[str]:
    """Schreibt ein DEP-5-Feld; mehrzeilige Werte werden gefaltet.

    ``schon_kodiert`` gilt fuer Werte, die bereits in DEP-5-Kodierung vorliegen
    und nur noch eingerueckt werden duerfen -- siehe :func:`einruecken_dep5`.
    """
    if "\n" not in wert:
        return [f"{name}: {wert}"]
    erste, rest = wert.split("\n", 1)
    zeilen = [f"{name}: {erste}"] if erste.strip() else [f"{name}:"]
    zeilen.extend(einruecken_dep5(rest) if schon_kodiert else falte_dep5(rest))
    return zeilen


def lizenzkurzname(eintrag: dict[str, Any]) -> str:
    """Der Wert des ``License``-Feldes eines ``Files``-Absatzes.

    Die Aufstellung fuehrt auf der Ebene ``nativ`` im Feld ``lizenz_id``
    teilweise nicht nur den Bezeichner, sondern den ganzen ``License:``-Block
    der Debian-copyright-Datei -- also Bezeichner UND eingerueckten Text. Das
    ist genau die Form, die DEP-5 an dieser Stelle vorsieht; sie wird
    unveraendert uebernommen (Regel 3) und nur wieder eingerueckt.
    """
    roh = eintrag.get("lizenz_id")
    if roh is None or not str(roh).strip():
        return OHNE_BEZEICHNER
    return str(roh)


def urhebervermerk(eintrag: dict[str, Any]) -> str:
    """Der Wert des ``Copyright``-Feldes; Negativbefund statt Erfindung."""
    roh = eintrag.get("urhebervermerk")
    if roh is None or not str(roh).strip():
        return OHNE_VERMERK
    return str(roh)


def files_muster(eintrag: dict[str, Any]) -> str:
    """Das ``Files``-Muster eines Bestandteils.

    Die Aufstellung fuehrt keine Dateilisten je Bestandteil -- die
    Fremdbestandteile stecken uebersetzt in den mitgelieferten Binaries und
    haben dort keine eigenen Pfade. Ein erfundenes Pfadmuster waere eine
    Behauptung; stattdessen benennt das Feld den Bestandteil eindeutig ueber
    Ebene, Name und Fassung. Die Fassung gehoert dazu, weil dieselbe Bibliothek
    mehrfach in verschiedenen Fassungen mitgeliefert wird (gemessen: 26 Faelle)
    und die Absaetze sonst nicht unterscheidbar waeren.
    """
    ebene = eintrag["ebene"]
    name = eintrag["name"]
    fassung = eintrag.get("fassung")
    if fassung:
        return f"{ebene}/{name}/{fassung}"
    return f"{ebene}/{name}"


def absatz_werk(daten: dict[str, Any]) -> list[str]:
    """Der ``Files: *``-Absatz des eigenen Werks."""
    werk = daten["werk"]
    zeilen = ["Files: *"]
    urheber = werk.get("urheber")
    zeilen.extend(feld("Copyright", urheber if urheber else OHNE_VERMERK))
    bezeichner = werk.get("lizenz_id")
    zeilen.extend(feld("License", bezeichner if bezeichner else OHNE_BEZEICHNER))
    return zeilen


def absatz_bestandteil(eintrag: dict[str, Any]) -> list[str]:
    """Ein ``Files``-Absatz je mitgeliefertem Fremdbestandteil."""
    zeilen = [f"Files: {files_muster(eintrag)}"]
    zeilen.extend(feld("Copyright", urhebervermerk(eintrag)))
    zeilen.extend(feld("License", lizenzkurzname(eintrag)))
    return zeilen


def absatz_nativ(eintrag: dict[str, Any]) -> list[str]:
    """Ein ``Files``-Absatz je mitgelieferter nativer Bibliothek.

    ``License`` wird hier als BEREITS KODIERT behandelt: die Aufstellung
    uebernimmt fuer diese Ebene den ganzen ``License:``-Block der
    Debian-copyright-Datei samt seiner ``.``-Zeilen. Der Urhebervermerk ist
    davon nicht betroffen -- er fuehrt gemessen weder Punkt- noch Leerzeilen.
    """
    zeilen = [f"Files: nativ/{eintrag['dateiname']}"]
    zeilen.extend(feld("Copyright", urhebervermerk(eintrag)))
    zeilen.extend(feld("License", lizenzkurzname(eintrag), schon_kodiert=True))
    return zeilen


def baue_copyright(daten: dict[str, Any]) -> str:
    """Baut die vollstaendige DEP-5-copyright."""
    werk = daten["werk"]
    kopf = [
        f"Format: {DEP5_FORMAT}",
        f"Upstream-Name: {werk['name']}",
    ]
    # Source ist in DEP-5 optional. Die Aufstellung fuehrt fuer das Werk keine
    # Projektadresse -- nach Regel 2 wird deshalb keine erfunden, das Feld
    # entfaellt ersatzlos.
    kopf.append("Comment:")
    kopf.extend(
        falte_dep5(
            "Diese Datei ist aus der Lizenzaufstellung des Bauvorgangs erzeugt\n"
            "(lizenzaufstellung.json) und fuehrt das eigene Werk sowie jeden\n"
            "mitgelieferten Fremdbestandteil.\n"
            "\n"
            "Die Volltexte der Fremdlizenzen stehen in der Datei\n"
            "3rd-party-licenses.txt.gz im selben Verzeichnis. Die Files-Muster\n"
            "benennen den Bestandteil nach Ebene, Name und Fassung: die\n"
            "Fremdbestandteile stecken uebersetzt in den mitgelieferten Binaries\n"
            "und haben dort keine eigenen Dateipfade.\n"
            "\n"
            "Wo zu einem Bestandteil kein Urhebervermerk oder kein\n"
            "Lizenzbezeichner belegt ist, sagt das Feld das ausdruecklich. Es\n"
            "wird an keiner Stelle eine Angabe angenommen, ergaenzt oder\n"
            "uebersetzt."
        )
    )

    absaetze: list[list[str]] = [kopf, absatz_werk(daten)]

    # Nur MITGELIEFERTE Bestandteile. Die Ebene "programme" fuehrt aufgerufene,
    # nicht mitgelieferte Fremdprogramme (mitgeliefert=false); sie gehoeren
    # nicht in die copyright eines Pakets, das sie nicht ausliefert.
    for eintrag in daten["bestandteile"]:
        if eintrag.get("mitgeliefert"):
            absaetze.append(absatz_bestandteil(eintrag))

    for eintrag in daten["ebene_nativ"]["eintraege"]:
        absaetze.append(absatz_nativ(eintrag))

    return "\n\n".join("\n".join(a) for a in absaetze) + "\n"


def baue_lizenztexte(daten: dict[str, Any]) -> str:
    """Baut die Sammlung der Lizenz-Volltexte (Datei 2)."""
    texte = daten["lizenztexte"]
    teile = [SAMMLUNG_KOPF]
    for schluessel in sorted(texte):
        eintrag = texte[schluessel]
        trenner = "=" * 78
        kopf = (
            f"{trenner}\n"
            f"Lizenztext: {schluessel}\n"
            f"Herkunft:   {eintrag['herkunft']}\n"
            f"Quelle:     {eintrag['quelle']}\n"
            f"Zeichen:    {eintrag['zeichen']}\n"
            f"SHA-256:    {eintrag['sha256']}\n"
            f"{trenner}\n"
        )
        # Der Text selbst: zeichengleich, ohne jede Nachbearbeitung (Regel 3).
        teile.append(kopf + "\n" + eintrag["text"])
    return "\n\n".join(teile) + "\n"


def _entfalte_feld(zeilen: list[str]) -> str:
    """Macht die DEP-5-Faltung rueckgaengig -- Gegenprobe zu Regel 3.

    Erste Zeile ist ``Feld: wert``; Folgezeilen tragen ein fuehrendes
    Leerzeichen, ``.`` steht fuer die Leerzeile und ``. .`` fuer eine Zeile, die
    selbst nur aus einem Punkt besteht.
    """
    erste = zeilen[0].split(": ", 1)[1] if ": " in zeilen[0] else ""
    teile = [erste]
    for zeile in zeilen[1:]:
        rest = zeile[1:] if zeile.startswith(" ") else zeile
        if rest == ".":
            teile.append("")
        elif rest == ". .":
            teile.append(".")
        else:
            teile.append(rest)
    return "\n".join(teile)


def pruefe_regel3(daten: dict[str, Any]) -> None:
    """Belegt maschinell, dass die Faltung keinen Wert veraendert.

    Jeder mehrzeilige Wert wird gefaltet und sofort wieder entfaltet; kommt
    nicht zeichengleich derselbe Wert heraus, bricht das Werkzeug ab. Die Ebene
    ``nativ`` ist ausgenommen, weil ihre ``lizenz_id`` bereits kodiert ankommt
    und nur eingerueckt wird -- dort prueft :func:`pruefe_nativ_unveraendert`.
    """
    for eintrag in daten["bestandteile"]:
        if not eintrag.get("mitgeliefert"):
            continue
        for name, wert in (
            ("Copyright", urhebervermerk(eintrag)),
            ("License", lizenzkurzname(eintrag)),
        ):
            if "\n" not in wert:
                continue
            if _entfalte_feld(feld(name, wert)) != wert:
                raise SystemExit(f"{eintrag['name']}: Faltung von {name} ist nicht umkehrbar")


def pruefe_nativ_unveraendert(daten: dict[str, Any], copyright_text: str) -> None:
    """Belegt, dass die nativen ``License``-Bloecke zeichengleich erscheinen.

    Geprueft wird gegen den fertigen Dateitext: aus jedem Absatz wird der
    ``License``-Block zurueckgelesen (fuehrendes Leerzeichen je Folgezeile
    entfernt) und mit dem Wert der Aufstellung verglichen.
    """
    absaetze = {}
    for absatz in copyright_text.split("\n\n"):
        zeilen = absatz.split("\n")
        if not zeilen[0].startswith("Files: nativ/"):
            continue
        absaetze[zeilen[0][len("Files: nativ/") :]] = zeilen

    for eintrag in daten["ebene_nativ"]["eintraege"]:
        roh = eintrag.get("lizenz_id")
        if roh is None or "\n" not in str(roh):
            continue
        zeilen = absaetze[eintrag["dateiname"]]
        start = next(i for i, z in enumerate(zeilen) if z.startswith("License:"))
        block = [zeilen[start][len("License: ") :]]
        for zeile in zeilen[start + 1 :]:
            if not zeile.startswith(" "):
                break
            block.append(zeile[1:])
        if "\n".join(block) != str(roh):
            raise SystemExit(f"{eintrag['dateiname']}: License-Block weicht von der Aufstellung ab")


def pruefe(daten: dict[str, Any], copyright_text: str) -> None:
    """Prueft die Zusagen, bevor geschrieben wird. Verstoss = Abbruch."""
    pruefe_regel3(daten)
    pruefe_nativ_unveraendert(daten, copyright_text)
    # Jeder mitgelieferte Bestandteil und jede native Bibliothek hat genau einen
    # Absatz. Eine stille Auslassung waere schlimmer als ein Abbruch.
    erwartet = sum(1 for e in daten["bestandteile"] if e.get("mitgeliefert"))
    erwartet += len(daten["ebene_nativ"]["eintraege"])
    gezaehlt = sum(1 for z in copyright_text.split("\n") if z.startswith("Files: "))
    # +1 fuer den Absatz "Files: *" des eigenen Werks.
    if gezaehlt != erwartet + 1:
        raise SystemExit(f"copyright fuehrt {gezaehlt} Files-Absaetze, erwartet {erwartet + 1}")
    # Kein Absatz darf ohne Copyright- oder License-Feld bleiben.
    for absatz in copyright_text.split("\n\n"):
        if not absatz.startswith("Files:"):
            continue
        if "\nCopyright:" not in absatz and not absatz.startswith("Copyright:"):
            raise SystemExit(f"Absatz ohne Copyright-Feld:\n{absatz[:200]}")
        if "\nLicense:" not in absatz:
            raise SystemExit(f"Absatz ohne License-Feld:\n{absatz[:200]}")


def main(argv: list[str] | None = None) -> int:
    zerleger = argparse.ArgumentParser(
        description=(
            "Erzeugt aus der Lizenzaufstellung die Debian-copyright (DEP-5) und "
            "die Sammlung der Lizenz-Volltexte."
        )
    )
    zerleger.add_argument("aufstellung", type=Path, help="Pfad der Lizenzaufstellung (JSON)")
    zerleger.add_argument(
        "--copyright", type=Path, required=True, help="Zielpfad der copyright-Datei"
    )
    zerleger.add_argument(
        "--lizenztexte",
        type=Path,
        required=True,
        help="Zielpfad der gzip-gepackten Volltextsammlung",
    )
    argumente = zerleger.parse_args(argv)

    if not argumente.aufstellung.is_file():
        raise SystemExit(f"Aufstellung nicht gefunden: {argumente.aufstellung}")
    daten = json.loads(argumente.aufstellung.read_text(encoding="utf-8"))

    copyright_text = baue_copyright(daten)
    pruefe(daten, copyright_text)
    sammlung = baue_lizenztexte(daten)

    argumente.copyright.parent.mkdir(parents=True, exist_ok=True)
    argumente.copyright.write_text(copyright_text, encoding="utf-8")
    argumente.lizenztexte.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0: derselbe Eingang ergibt dasselbe Ergebnis, Byte fuer Byte. Sonst
    # traegt jeder Bau einen anderen Zeitstempel im gzip-Kopf.
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=argumente.lizenztexte.open("wb"), mtime=0
    ) as strom:
        strom.write(sammlung.encode("utf-8"))

    absaetze = sum(1 for z in copyright_text.split("\n") if z.startswith("Files: "))
    ohne_vermerk = copyright_text.count(OHNE_VERMERK)
    ohne_bezeichner = copyright_text.count(OHNE_BEZEICHNER)
    print(f"geschrieben: {argumente.copyright}")
    print(f"  Files-Absaetze           {absaetze:>4}")
    print(f"  ohne Urhebervermerk      {ohne_vermerk:>4}")
    print(f"  ohne Lizenzbezeichner    {ohne_bezeichner:>4}")
    print(f"geschrieben: {argumente.lizenztexte}")
    print(f"  Lizenztexte              {len(daten['lizenztexte']):>4}")
    print(f"  ungepackt {len(sammlung.encode('utf-8')):>9} Byte")
    print(f"  gepackt   {argumente.lizenztexte.stat().st_size:>9} Byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
