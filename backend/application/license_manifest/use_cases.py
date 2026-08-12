"""Use-Cases der Lizenzaufstellung: Liste ohne Texte + einzelner Volltext.

Orchestrieren den Port (``LicenseManifestPort``) und das reine Normalisierungsmodul.
Kennen ``ports/``, NIEMALS ``infrastructure/`` (maschinell per import-linter
erzwungen). Der Port kommt per Constructor-Injection als Protocol-Typ herein -- nie
ein konkreter Adapter. Kein State ueber Aufrufe, keine Framework-Imports.

ZWEI Use-Cases, weil die Datei zu 75,6 Prozent aus Lizenztexten besteht:

* ``GetLicenseManifest`` -- die Aufstellung OHNE ``lizenztexte``: Kopf, ``werk``,
  ``bestandteile`` (angereichert), ``luecken``, ``ebene_nativ``. Ein Zug, 175664 B
  statt 720349 B.
* ``GetLicenseText`` -- ein einzelner Volltext auf Abruf, zeichengleich.

ZWEI ANREICHERUNGEN je Bestandteil, beide ADDITIV -- kein Feld der Aufstellung wird
ueberschrieben, gekuerzt oder umgeschrieben:

* ``lizenz_id_normalisiert`` -- der Filterindex (siehe ``normalisierung.py``).
  ``lizenz_id`` selbst bleibt roh und unveraendert.
* ``vorhanden`` (NUR fuer die Ebene ``programme``) -- was auf DIESER Installation
  gefunden wurde. Die Datei sagt, was VORAUSGESETZT wird; das Backend sagt, was
  GEFUNDEN wurde. Getrennte Felder, damit die Oberflaeche beides zeigen kann, ohne
  das eine fuer das andere zu halten.

DIE PLATTFORM KOMMT VON AUSSEN (Aufgabe 2b, letzter Punkt): ``__call__`` nimmt sie
als Parameter. Der Use-Case ermittelt sie NICHT selbst aus ``sys.platform`` -- das
macht der Composition Root und uebergibt sie. So bleibt der Use-Case ohne
Plattform-Wissen und im Test ohne Monkeypatch pruefbar.

DIE PLATTFORMEIGENE PRUEFUNG KOMMT EBENSO VON AUSSEN (Befund 54b): nicht jeder
Eintrag der Ebene ``programme`` ist eine Datei im Suchpfad. Npcap ist ein
Kerneltreiber ohne ausfuehrbare Datei -- ``shutil.which`` faende ihn nie und
meldete auf Windows dauerhaft "fehlt", obwohl er eingerichtet ist. Fuer solche
Eintraege nimmt der Use-Case eine NAHT (``ProgrammPruefung``) entgegen, die der
Composition Root auf dieselbe Quelle verdrahtet wie den Npcap-Marker. Der
application-Ring nennt dabei WEDER ``sniffd_client`` NOCH eine Plattform -- er
kennt nur eine Abbildung Name -> Befund. Liefert die Naht nichts oder ist sie gar
nicht gesetzt, steht dort ``nicht_ermittelbar``: ein EIGENER, benannter Zustand,
kein Rueckfall auf "fehlt" oder "vorhanden" (Finding S3).

DER WERK-LIZENZTEXT WIRD HIER AUFGELOEST (Befund 54b, Teil 2): die Aufstellung
traegt in ``werk.lizenz_text`` die REFERENZ (``werk:GPL-2.0-only``), nicht den
Text. Die Ansicht zeigte diese Zeichenkette bisher woertlich im Aufklappblock. Der
Use-Case ersetzt sie durch den Volltext aus ``lizenztexte``. Die Ebene
``lizenztexte`` selbst geht weiterhin NICHT hinaus -- sie ist der Grund fuer den
zweiten Endpunkt; hier wird genau EIN Eintrag daraus nachgeschlagen.

LIZENZTEXTE WERDEN NIE VERAENDERT (Aufgabe 2c): ``GetLicenseText`` reicht den Text
des Ports unveraendert durch -- nicht gekuerzt, nicht umbrochen, nicht uebersetzt.
Dasselbe gilt fuer den hier aufgeloesten Werk-Text.
"""

import shutil
from collections.abc import Callable
from typing import Any

from application.license_manifest.errors import (
    LicenseManifestUnavailable,
    LicenseTextUnknown,
)
from application.license_manifest.normalisierung import normalisiere_lizenz_id
from ports.license_manifest import (
    LicenseManifestPort,
    LicenseManifestPortError,
    LicenseTextNotFoundError,
)

# Die Ebene, deren Bestandteile vorausgesetzte externe PROGRAMME sind (19 Eintraege).
# Nur fuer sie wird das Vorhandensein erhoben -- ein Rust-Crate oder ein npm-Paket ist
# keine Datei im PATH, die Frage waere dort sinnlos.
_EBENE_PROGRAMME = "programme"

# Die VIER Zustaende des Vorhandensein-Feldes. ``nicht_zutreffend`` ist der DRITTE
# Zustand (Aufgabe 2b): das Programm gehoert zu einer anderen Plattform, es fehlt hier
# also nicht -- es ist hier schlicht nicht gemeint. Ohne diesen Zustand laese sich ein
# Windows-Werkzeug auf macOS als "fehlt" -- eine Falschaussage.
#
# ``nicht_ermittelbar`` ist der VIERTE (Befund 54b): der Eintrag ist auf dieser
# Plattform gemeint, aber es gibt hier keine Pruefung, die ihn beantworten koennte
# -- weil er nicht ueber den Suchpfad auffindbar ist und die plattformeigene Naht
# fehlt oder nichts liefert. Er ist AUSDRUECKLICH kein Synonym fuer "fehlt": ein
# eingerichteter Kerneltreiber, den niemand geprueft hat, ist nicht abwesend, er ist
# ungeprueft. Die Falschaussage waere hier gerade der Rueckfall (Finding S3).
_VORHANDEN = "vorhanden"
_FEHLT = "fehlt"
_NICHT_ZUTREFFEND = "nicht_zutreffend"
_NICHT_ERMITTELBAR = "nicht_ermittelbar"

# Plattform-Bezeichner der Aufstellung, der ALLE Plattformen meint (Eintrag ``nmap``).
# Vergleich in Kleinschreibung, damit die Schreibung des Feldes nicht traegt.
_PLATTFORM_ALLE = "alle"

# Trennzeichen des Feldes ``plattform``, das mehrere Plattformen fuehrt -- gemessen
# ``Linux/macOS/Windows`` und ``macOS/Windows``.
_PLATTFORM_TRENNER = "/"

# Trennzeichen des Feldes ``name``, wenn EIN Eintrag mehrere austauschbare Programme
# meint -- gemessen genau einmal: ``apt, dnf, yum, zypper, pacman`` (die
# Paketverwaltungen der verschiedenen Linux-Distributionen). Fuer diesen Eintrag gilt
# das Vorhandensein als erfuellt, sobald EINES der genannten Programme da ist: der
# Zweck ist die Paketverwaltung, und davon traegt jede Distribution genau eine.
_NAME_TRENNER = ","

# Die Abstufung des Feldes ``bezugsart``, bei der ``shutil.which`` NICHT entscheiden
# darf (Befund 54b). ``vorausgesetzt`` heisst gemessen: das Programm wird nie
# aufgerufen -- es gibt also keinen Prozessstart und damit auch keinen Grund, warum
# eine ausfuehrbare Datei im Suchpfad liegen sollte. Genau darauf sucht
# ``shutil.which`` aber, und ein Nichtfund waere dort kein Befund, sondern die
# falsche Frage.
#
# Bewusst an der BEZUGSART festgemacht und nicht an einem Namen: eine Namensliste im
# application-Ring waere Plattform- und Produktwissen an der falschen Stelle und
# veraltete beim naechsten Eintrag still. Die Bezugsart steht in der Aufstellung, ist
# dort begruendet und traegt sich selbst.
_BEZUGSART_OHNE_SUCHPFAD = "vorausgesetzt"

# Die Naht fuer den Vorhandenseins-Befund derjenigen Eintraege, die nicht ueber den
# Suchpfad auffindbar sind (Befund 54b). Sie bekommt den NAMEN des Eintrags und
# liefert:
#
#   True  -- die plattformeigene Pruefung hat es gefunden
#   False -- die plattformeigene Pruefung hat es NICHT gefunden
#   None  -- keine Aussage moeglich (nicht zustaendig, nicht verfuegbar)
#
# Die Dreiwertigkeit ist der Kern: ohne sie liesse sich "nicht gefunden" nicht von
# "nicht geprueft" unterscheiden, und genau diese Verwechslung ist Befund 54b.
#
# Sie ist quellen-AGNOSTISCH -- wie ``DnsBypassPermissionCheck`` in Befund 52: der
# application-Ring nennt weder ``sniffd_client`` noch eine Plattform; die echte
# Verdrahtung faellt im Composition Root (Importregel 5). Ist die Naht ``None``,
# gibt es keine Pruefung, und der Zustand heisst ``nicht_ermittelbar``.
ProgrammPruefung = Callable[[str], bool | None]


class GetLicenseManifest:
    """Die Aufstellung OHNE Lizenztexte, je Bestandteil additiv angereichert.

    Sequenz: Aufstellung ueber den Port holen -> Kopf und die vier Abschnitte
    uebernehmen -> je Bestandteil den normalisierten Bezeichner anhaengen -> fuer die
    Ebene ``programme`` zusaetzlich das Vorhandensein erheben.

    Die Ebene ``lizenztexte`` wird NICHT durchgereicht -- sie ist der Grund fuer den
    zweiten Endpunkt. Fehlt die Aufstellung, ist das ``LicenseManifestUnavailable``,
    NIEMALS eine leere Aufstellung (Finding S3).

    ``programm_pruefung`` ist die optionale Naht aus Befund 54b (siehe
    ``ProgrammPruefung``). Ohne sie bleibt jeder Eintrag ohne Suchpfad-Bezug auf
    ``nicht_ermittelbar``; das Verhalten aller uebrigen Eintraege aendert sich nicht.
    """

    def __init__(
        self,
        manifest: LicenseManifestPort,
        programm_pruefung: ProgrammPruefung | None = None,
    ) -> None:
        self._manifest = manifest
        self._programm_pruefung = programm_pruefung

    def __call__(self, *, plattform: str) -> dict[str, Any]:
        """``plattform`` ist der Bezeichner der laufenden Plattform, von aussen gesetzt.

        Erwartete Werte sind die der Aufstellung: ``Linux``, ``macOS``, ``Windows``.
        Der Vergleich laeuft in Kleinschreibung, damit die Schreibung nicht traegt.
        """
        try:
            aufstellung = self._manifest.load()
        except LicenseManifestPortError as exc:
            # Port-Fehler in den application-Ring uebersetzen: der api-Ring darf weder
            # ports noch infrastructure importieren und kann die Klasse daher nicht
            # fangen. LAUT weitergereicht -- kein Rueckfall auf eine leere Aufstellung
            # (Finding S3).
            raise LicenseManifestUnavailable(str(exc)) from exc

        bestandteile = aufstellung.get("bestandteile")
        roh_liste: list[Any] = bestandteile if isinstance(bestandteile, list) else []
        return {
            # Kopf.
            "schema_version": aufstellung.get("schema_version"),
            "erzeugt_am": aufstellung.get("erzeugt_am"),
            "produktversion": aufstellung.get("produktversion"),
            "plattform": aufstellung.get("plattform"),
            # Die vier Abschnitte. ``luecken``/``ebene_nativ`` gehen unveraendert
            # durch; ``bestandteile`` wird additiv angereichert, und in ``werk``
            # wird genau EIN Feld aufgeloest (Befund 54b, Teil 2).
            "werk": self._werk_mit_lizenztext(aufstellung),
            "bestandteile": [
                self._anreichern(teil, plattform=plattform)
                for teil in roh_liste
                if isinstance(teil, dict)
            ],
            "luecken": aufstellung.get("luecken"),
            "ebene_nativ": aufstellung.get("ebene_nativ"),
        }

    @staticmethod
    def _werk_mit_lizenztext(aufstellung: dict[str, Any]) -> Any:
        """Loest ``werk.lizenz_text`` von der REFERENZ auf den Volltext auf.

        Befund 54b, Teil 2: der Sammler legt den Volltext der Wurzel-LICENSE in
        ``lizenztexte`` ab und schreibt in ``werk.lizenz_text`` nur dessen
        SCHLUESSEL (gemessen ``werk:GPL-2.0-only``). Die Ansicht zeigte diese
        Zeichenkette woertlich im Aufklappblock -- an der Stelle, an der der
        Lizenztext stehen muesste. Der ehrliche Ersatzhinweis griff nicht, weil das
        Feld ja belegt war, nur eben mit dem falschen Inhalt.

        Aufgeloest wird an DIESER Stelle, nicht in der Ansicht: der Adapter haelt
        die Texte ohnehin, und ein zweiter Abruf allein fuer das eigene Werk waere
        ein Umweg ueber HTTP fuer etwas, das hier schon vorliegt.

        Die Ebene ``lizenztexte`` geht deshalb TROTZDEM nicht hinaus -- nur der eine
        nachgeschlagene Text. Bleibt die Referenz unaufloesbar (kein Eintrag, kein
        Text, leerer Text), bleibt das Feld unveraendert stehen und die Ansicht
        zeigt ihren vorhandenen Ersatzhinweis. Kein erfundener Text, keine leere
        Zeichenkette (Finding S3).
        """
        werk = aufstellung.get("werk")
        if not isinstance(werk, dict):
            return werk
        ref = werk.get("lizenz_text")
        if not isinstance(ref, str) or ref == "":
            return werk
        texte = aufstellung.get("lizenztexte")
        if not isinstance(texte, dict):
            return werk
        eintrag = texte.get(ref)
        if not isinstance(eintrag, dict):
            return werk
        text = eintrag.get("text")
        if not isinstance(text, str) or text == "":
            return werk
        # Flache Kopie wie bei den Bestandteilen: der Adapter haelt die Aufstellung,
        # ein Schreiben in seine Struktur wirkte bei jedem weiteren Abruf nach.
        aufgeloest = dict(werk)
        aufgeloest["lizenz_text"] = text
        return aufgeloest

    def _anreichern(self, teil: dict[str, Any], *, plattform: str) -> dict[str, Any]:
        """Ein Bestandteil plus die additiven Felder -- die Vorlage bleibt unberuehrt.

        Flache Kopie, damit die im Adapter gehaltene Aufstellung nicht mutiert wird:
        der Adapter liest genau einmal, ein Schreiben in seine Struktur wuerde bei
        jedem weiteren Abruf nachwirken.
        """
        angereichert = dict(teil)
        angereichert["lizenz_id_normalisiert"] = normalisiere_lizenz_id(teil.get("lizenz_id"))
        if teil.get("ebene") == _EBENE_PROGRAMME:
            angereichert["vorhanden"] = self._vorhandensein(teil, plattform=plattform)
        return angereichert

    def _vorhandensein(self, teil: dict[str, Any], *, plattform: str) -> str:
        """Einer der vier Zustaende fuer EIN vorausgesetztes Programm.

        Erhoben wird NUR, wenn das Feld ``plattform`` des Eintrags die laufende
        Plattform einschliesst -- sonst ``nicht_zutreffend``.

        WELCHE ERHEBUNG gilt, entscheidet die ``bezugsart`` des Eintrags:

        * ``vorausgesetzt`` (nie aufgerufen) -- die Naht ``programm_pruefung``, weil
          es hier keine ausfuehrbare Datei im Suchpfad gibt, nach der zu suchen
          waere. Fehlt die Naht oder liefert sie ``None``, ist das
          ``nicht_ermittelbar``. AUSDRUECKLICH KEIN Rueckfall auf ``shutil.which``:
          der faende nichts und meldete damit "fehlt" -- eine Aussage ueber
          Abwesenheit, die niemand geprueft hat (Finding S3, Befund 54b).
        * alles Uebrige -- ``shutil.which`` wie bisher (reine PATH-Suche, es wird
          NICHTS gestartet).
        """
        if not self._plattform_passt(teil.get("plattform"), laufend=plattform):
            return _NICHT_ZUTREFFEND
        name = teil.get("name")
        if not isinstance(name, str) or not name.strip():
            # Ein Eintrag ohne Namen ist nicht erhebbar -- kein Ratespiel, kein "fehlt".
            return _NICHT_ZUTREFFEND

        if teil.get("bezugsart") == _BEZUGSART_OHNE_SUCHPFAD:
            if self._programm_pruefung is None:
                return _NICHT_ERMITTELBAR
            befund = self._programm_pruefung(name)
            if befund is None:
                return _NICHT_ERMITTELBAR
            return _VORHANDEN if befund else _FEHLT

        # Ein Eintrag kann mehrere austauschbare Programme meinen (Paketverwaltungen);
        # EINES genuegt.
        kandidaten = [k.strip() for k in name.split(_NAME_TRENNER) if k.strip()]
        gefunden = any(shutil.which(kandidat) is not None for kandidat in kandidaten)
        return _VORHANDEN if gefunden else _FEHLT

    @staticmethod
    def _plattform_passt(feld: Any, *, laufend: str) -> bool:
        """Schliesst das Feld ``plattform`` des Eintrags die laufende Plattform ein?

        ``alle`` schliesst jede Plattform ein. Mehrfachangaben sind mit ``/`` getrennt
        (``Linux/macOS/Windows``). Fehlt das Feld oder ist es kein Text, gilt der
        Eintrag als NICHT zutreffend -- lieber keine Aussage als eine geratene.
        """
        if not isinstance(feld, str):
            return False
        genannt = {stueck.strip().lower() for stueck in feld.split(_PLATTFORM_TRENNER)}
        if _PLATTFORM_ALLE in genannt:
            return True
        return laufend.strip().lower() in genannt


class GetLicenseText:
    """EIN Lizenztext ueber seinen Schluessel -- zeichengleich, nie veraendert.

    Schluesselformen: ``paket:<ebene>/<name>``, ``spdx:<id>``, ``werk:<id>``.
    Unbekannter Schluessel -> ``LicenseTextUnknown`` (der api-Ring macht 404 daraus),
    NIE ein leerer Text (Finding S3).
    """

    def __init__(self, manifest: LicenseManifestPort) -> None:
        self._manifest = manifest

    def __call__(self, schluessel: str) -> str:
        try:
            return self._manifest.get_text(schluessel)
        except LicenseTextNotFoundError as exc:
            # Nur der Nichtfund EINES Schluessels ist eine 404-Sache.
            raise LicenseTextUnknown(str(exc)) from exc
        except LicenseManifestPortError as exc:
            # Alles Uebrige (fehlende/kaputte Aufstellung) ist ein Auslieferungsmangel.
            # Beides ist LAUT -- kein leerer Text als Rueckfall (Finding S3).
            raise LicenseManifestUnavailable(str(exc)) from exc
