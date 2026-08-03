"""Normalisierung roher Lizenzbezeichner -- ausschliesslich fuer den FILTER.

ENTSCHEIDUNG (4) DES AUFTRAGS: der rohe Wert (``lizenz_id``) bleibt UNVERAENDERT
erhalten und wird roh ausgeliefert; die Normalisierung kommt als ZUSAETZLICHES Feld
dazu. Die Regel "Anzeige unveraendert" gilt fuer die Anzeige, nicht fuer einen
Filterindex -- ohne den Index zerfaellt eine Filterliste in Schreibvarianten, die
gemessen dasselbe meinen.

DIE REGEL, IN VIER SCHRITTEN:

1. Aussenraum abschneiden (``strip``).
2. Den Schraegstrich als Trennzeichen durch ``OR`` ersetzen und Mehrfach-Leerraum
   auf ein Leerzeichen ziehen. Gemessen belegt: ``MIT/Apache-2.0`` (17x),
   ``Apache-2.0/MIT`` (1x), ``MIT / Apache-2.0`` (1x) und ``Apache-2.0 / MIT`` (1x)
   stehen neben ``MIT OR Apache-2.0`` (127x) und ``Apache-2.0 OR MIT`` (26x) --
   derselbe Sachverhalt in vier Schreibweisen.
3. Die Teilausdruecke einer reinen ``OR``-Kette alphabetisch sortieren und Dubletten
   entfernen. Gemessen belegt: ``MIT OR Apache-2.0 OR Zlib`` / ``MIT OR Zlib OR
   Apache-2.0`` / ``Zlib OR Apache-2.0 OR MIT`` sind dieselbe Wahlmoeglichkeit in
   drei Reihenfolgen. ``OR`` ist kommutativ, die Reihenfolge traegt keine Bedeutung.
4. Bekannte Namensvarianten EINES Bezeichners vereinheitlichen: ``MIT License``
   (1x) -> ``MIT`` (83x). Die Tabelle ``_NAMENSVARIANTEN`` fuehrt AUSSCHLIESSLICH
   gemessen vorkommende Varianten -- keine erfundene Zuordnung, die die Datei nicht
   hergibt.

BEWUSST UNANGETASTET BLEIBEN zwei Ausdrucksformen, weil dort die Reihenfolge sehr
wohl Bedeutung traegt und ein Sortieren den Ausdruck VERFAELSCHEN wuerde:

* Ausdruecke mit Klammern -- ``(MIT OR Apache-2.0) AND Unicode-3.0``: die Klammer
  bindet, eine flache Sortierung wuerde die Bindung zerreissen.
* Ausdruecke, in deren Teilen ``AND`` oder ``WITH`` steht -- ``Apache-2.0 AND MIT``,
  ``BSD-3-Clause AND MIT``, ``Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT``:
  ``AND`` ist eine Verpflichtung auf BEIDE Lizenzen (nicht eine Wahl), ``WITH``
  bindet eine Ausnahme an genau einen Bezeichner. Beide werden nur getrimmt und im
  Leerraum vereinheitlicht, sonst nicht umgestellt.

WIRKUNG, GEMESSEN: aus 35 rohen Ausdruecken werden 26 normalisierte. Zusammengefuehrt
werden genau vier Gruppen -- die MIT/Apache-2.0-Familie (6 Schreibweisen -> 1),
die MIT/Zlib/Apache-2.0-Familie (3 -> 1), ``MIT`` + ``MIT License`` (2 -> 1) und
``Unlicense OR MIT`` + ``Unlicense/MIT`` (2 -> 1). ``BSD-3-Clause/MIT`` wird zu
``BSD-3-Clause OR MIT`` (ohne Partner, aber schreibweisen-einheitlich).

Ist ``lizenz_id`` ``None`` (20 Bestandteile), bleibt auch das Zusatzfeld ``None`` --
es wird KEINE Lizenz erraten, wo die Aufstellung keine ausweist.

Reines Modul ohne Seiteneffekte und ohne Fremdimporte -- weder ``ports`` noch
``domain`` noch ``infrastructure``.
"""

# Trennzeichen und Verknuepfungen des SPDX-Ausdrucks. ``OR`` ist eine Wahl (kommutativ,
# darum sortierbar), ``AND`` eine Verpflichtung auf beide und ``WITH`` eine Bindung an
# genau einen Bezeichner (beide NICHT sortierbar).
_ODER = " OR "
_NICHT_UMSTELLBAR = (" AND ", " WITH ")

# Gemessen vorkommende Namensvarianten EINES Bezeichners. Der Schluessel wird in
# Grossschreibung verglichen, damit die Tabelle nicht an der Schreibung des Vergleichs
# haengt. AUSSCHLIESSLICH belegte Varianten -- diese Tabelle waechst nur mit einer
# Messung, nie mit einer Vermutung.
_NAMENSVARIANTEN = {
    "MIT LICENSE": "MIT",
}


def normalisiere_lizenz_id(roh: str | None) -> str | None:
    """Normalisierte Form eines rohen Lizenzbezeichners -- fuer den Filter.

    ``None`` bleibt ``None`` (kein Raten). Ein Ausdruck, der nur aus Leerraum
    besteht, ergibt ebenfalls ``None``: eine leere Zeichenkette waere ein eigener,
    sinnloser Filterwert.

    Der uebergebene Wert wird NICHT veraendert -- die Funktion ist rein und liefert
    einen neuen String; ``lizenz_id`` selbst bleibt beim Aufrufer unangetastet.
    """
    if roh is None:
        return None

    # Schritt 1+2: trimmen, Schraegstrich -> OR, Leerraum vereinheitlichen.
    ausdruck = " ".join(roh.replace("/", _ODER).split())
    if not ausdruck:
        return None

    # Klammern und AND/WITH: nur die Schreibweise vereinheitlicht, die Struktur bleibt.
    # Ein Sortieren wuerde hier die Bedeutung verfaelschen (siehe Modul-Docstring).
    if "(" in ausdruck or ")" in ausdruck:
        return ausdruck
    teilausdruecke = ausdruck.split(_ODER)
    if any(marke in teil for teil in teilausdruecke for marke in _NICHT_UMSTELLBAR):
        return ausdruck

    # Schritt 4 vor Schritt 3: erst die Namensvarianten vereinheitlichen, dann
    # sortieren -- sonst sortierte "MIT License" an einer anderen Stelle als "MIT"
    # und eine Dublette bliebe unerkannt.
    vereinheitlicht = [_NAMENSVARIANTEN.get(teil.upper(), teil) for teil in teilausdruecke]
    return _ODER.join(sorted(set(vereinheitlicht)))
