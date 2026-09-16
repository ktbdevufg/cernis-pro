"""Port der Lizenzaufstellung: Vertrag fuer den Zugriff auf ``lizenzaufstellung.json``.

Ein Vertrag:

* ``LicenseManifestPort`` -- liefert (1) die Aufstellung als GANZES und (2) einen
  einzelnen Lizenztext ueber seinen Schluessel.

Warum ZWEI Methoden und nicht nur ``load``: 75,6 Prozent der Datei sind Lizenztexte
(720349 B gesamt, 175664 B ohne ``lizenztexte``). Der Use-Case liefert die Liste
darum OHNE Texte und holt einen Volltext nur auf Abruf. Der Port bildet genau diese
zwei Zugriffe ab, statt den Use-Case zwingen, jedes Mal alles durchzureichen.

``get_text`` bleibt trotzdem am Port und wird nicht im Use-Case aus ``load``
herausgegriffen: WO der Text herkommt, ist Adapter-Sache -- ein spaeterer Adapter
koennte die Texte einzeln von der Platte holen, statt sie im Speicher zu halten. Der
Vertrag laesst beides zu.

EHRLICHER LEERZUSTAND (Finding S3): es gibt hier KEINEN. Weder ``load`` noch
``get_text`` duerfen ein leeres Ergebnis als Auskunft liefern -- eine fehlende Datei
und ein unbekannter Schluessel sind je ein BENANNTER Fehler des Adapters, kein leeres
``dict`` und kein leerer String. Eine leere Aufstellung waere eine Falschaussage
("dieses Produkt verwendet nichts Fremdes"), ein leerer Lizenztext ebenso.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie interfaces/settings/
devices/scanning). Die Vertragspruefung laeuft statisch ueber mypy und ueber die
Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

Beide Methoden sind SYNCHRON (anders als ``InterfaceDiscoveryPort.discover``): der
Adapter liest die Datei genau einmal und haelt sie danach im Speicher -- es gibt kein
wiederkehrendes blockierendes I/O, das eine ``async``-Kapselung rechtfertigen wuerde.

Der Rueckgabetyp ist ``dict[str, Any]`` bzw. ``str``, KEIN Domaenenmodell: die
Aufstellung ist ein erzeugtes Bau-Artefakt mit eigenem ``schema_version``, kein
Fachobjekt dieser Anwendung. Ein ``domain``-Import findet hier deshalb nicht statt.
"""

from typing import Any, Protocol


class LicenseManifestPortError(Exception):
    """Basis der Fehler, die der Port zusagt.

    Die Fehlerklassen gehoeren zum VERTRAG, nicht zum Adapter: nur so kann der
    ``application``-Ring die Faelle unterscheiden, ohne ``infrastructure`` zu
    importieren (import-linter verbietet das). Der Adapter leitet seine Klassen von
    diesen ab; der Use-Case faengt die Port-Klassen.
    """


class LicenseManifestUnavailableError(LicenseManifestPortError):
    """Die Aufstellung ist nicht auffindbar oder nicht lesbar.

    Bei einem Nichtfund traegt die Meldung die vollstaendige Liste der geprueften
    Pfade -- damit im Betrieb nachvollziehbar bleibt, wo gesucht wurde.
    """


class LicenseTextNotFoundError(LicenseManifestPortError):
    """Der angefragte Lizenztext-Schluessel steht nicht in der Aufstellung.

    Bewusst ein eigener Fehler und kein leerer String: ein leerer Lizenztext waere
    eine Falschaussage ueber die Lizenzlage, kein ehrlicher Leerfall.
    """


class LicenseManifestPort(Protocol):
    """Zugriff auf die im Bauvorgang erzeugte Lizenzaufstellung."""

    def load(self) -> dict[str, Any]:
        """Die vollstaendige Aufstellung, inklusive ``lizenztexte``.

        Oberste Ebenen: ``schema_version``, ``erzeugt_am``, ``produktversion``,
        ``plattform``, ``werk``, ``bestandteile`` (Liste), ``lizenztexte`` (Objekt),
        ``luecken`` (Liste), ``ebene_nativ``.

        KEIN Leerzustand: ist keine Aufstellung auffindbar oder die gefundene nicht
        lesbar, ist das ``LicenseManifestUnavailableError`` -- niemals ein leeres
        ``dict``.
        """
        ...

    def get_text(self, schluessel: str) -> str:
        """Ein einzelner Lizenztext, ZEICHENGLEICH wie in der Aufstellung.

        Schluesselformen: ``paket:<ebene>/<name>``, ``spdx:<id>``, ``werk:<id>``.

        Der Text wird NIE veraendert -- nicht gekuerzt, nicht umbrochen, nicht
        uebersetzt. Ein unbekannter Schluessel ist ``LicenseTextNotFoundError``, KEIN
        leerer String; eine fehlende/unlesbare Aufstellung ist
        ``LicenseManifestUnavailableError``.
        """
        ...
