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

LIZENZTEXTE WERDEN NIE VERAENDERT (Aufgabe 2c): ``GetLicenseText`` reicht den Text
des Ports unveraendert durch -- nicht gekuerzt, nicht umbrochen, nicht uebersetzt.
"""

import shutil
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

# Die drei Zustaende des Vorhandensein-Feldes. ``nicht_zutreffend`` ist der DRITTE
# Zustand (Aufgabe 2b): das Programm gehoert zu einer anderen Plattform, es fehlt hier
# also nicht -- es ist hier schlicht nicht gemeint. Ohne diesen Zustand laese sich ein
# Windows-Werkzeug auf macOS als "fehlt" -- eine Falschaussage.
_VORHANDEN = "vorhanden"
_FEHLT = "fehlt"
_NICHT_ZUTREFFEND = "nicht_zutreffend"

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


class GetLicenseManifest:
    """Die Aufstellung OHNE Lizenztexte, je Bestandteil additiv angereichert.

    Sequenz: Aufstellung ueber den Port holen -> Kopf und die vier Abschnitte
    uebernehmen -> je Bestandteil den normalisierten Bezeichner anhaengen -> fuer die
    Ebene ``programme`` zusaetzlich das Vorhandensein erheben.

    Die Ebene ``lizenztexte`` wird NICHT durchgereicht -- sie ist der Grund fuer den
    zweiten Endpunkt. Fehlt die Aufstellung, ist das ``LicenseManifestUnavailable``,
    NIEMALS eine leere Aufstellung (Finding S3).
    """

    def __init__(self, manifest: LicenseManifestPort) -> None:
        self._manifest = manifest

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
            # Die vier Abschnitte. ``werk``/``luecken``/``ebene_nativ`` gehen
            # unveraendert durch; nur ``bestandteile`` wird additiv angereichert.
            "werk": aufstellung.get("werk"),
            "bestandteile": [
                self._anreichern(teil, plattform=plattform)
                for teil in roh_liste
                if isinstance(teil, dict)
            ],
            "luecken": aufstellung.get("luecken"),
            "ebene_nativ": aufstellung.get("ebene_nativ"),
        }

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
        """``vorhanden`` / ``fehlt`` / ``nicht_zutreffend`` fuer EIN vorausgesetztes Programm.

        Erhoben wird NUR, wenn das Feld ``plattform`` des Eintrags die laufende
        Plattform einschliesst -- sonst ``nicht_zutreffend``. Die Erhebung selbst
        laeuft ueber ``shutil.which`` (reine PATH-Suche, es wird NICHTS gestartet).
        """
        if not self._plattform_passt(teil.get("plattform"), laufend=plattform):
            return _NICHT_ZUTREFFEND
        name = teil.get("name")
        if not isinstance(name, str) or not name.strip():
            # Ein Eintrag ohne Namen ist nicht erhebbar -- kein Ratespiel, kein "fehlt".
            return _NICHT_ZUTREFFEND
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
