"""Application-Exceptions der fritz_detail-Use-Cases.

Der einzige fachliche Fehler ist der FritzBox-AUTH-Fehler (falsche Credentials).
Im Unterschied zur scanning-Domaene -- wo der Auth-Fehler erst im Composition
Root (``ws_scan``) als Adapter-Exception gefangen und dort behandelt wird -- hat
``fritz_detail`` einen REST-Endpunkt im api-Ring (``GET /api/fritz/detail``). Der
api-Ring darf ``infrastructure`` laut import-linter NICHT importieren (Contract
"api ruft nur application"), kann die ``infrastructure``-``FritzAuthError`` also
nicht selbst fangen.

Darum ein application-EIGENER Fehlertyp ``FritzDetailAuthError`` (genau die in der
Aufgabe vorgesehene Alternative): der Composition Root (``app.py``, von den
Contracts ausgenommen) faengt die ``infrastructure``-``FritzAuthError`` des
Adapters und uebersetzt sie in diesen application-Typ -- den der Router dann sauber
(import-linter-konform) fangen und auf HTTP 502 mappen kann.
"""


class FritzDetailApplicationError(Exception):
    """Basis fuer Fehler der fritz_detail-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class FritzDetailAuthError(FritzDetailApplicationError):
    """FRITZ!Box-Authentifizierung gescheitert (falsche/fehlende Credentials).

    Application-Pendant der ``infrastructure``-``FritzAuthError`` -- damit der
    api-Ring den Auth-Fehler fangen kann, ohne ``infrastructure`` zu importieren.
    Die Uebersetzung passiert im Composition Root (``app.py``). Traegt den ``host``
    fuer die Diagnose.
    """

    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(f"FRITZ!Box {host!r}: Authentifizierung gescheitert (Credentials pruefen)")
