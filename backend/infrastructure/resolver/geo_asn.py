"""Adapter ``CsvGeoAsnDb`` fuer ``ports.resolver.GeoAsnDbPort`` -- lokaler CSV-Lookup.

Teilschritt 2d (letzter Quell-Adapter): rein lokaler Geo/ASN-Lookup aus vier CC0/PDDL-
CSVs in ``backend/data`` (je Familie+Quelle: asn-country v4/v6, iptoasn-asn v4/v6, KEINE
Kopfzeile, nach Range-Start aufsteigend, ueberlappungsfrei). Der Lookup ist SYNCHRON
(kein Netz-/Loop-I/O) -- genau wie der Port es vorgibt.

Gefuellt werden ``country`` (aus asn-country) und ``asn`` = die ASN-NUMMER als String
(aus iptoasn-asn, Spalte 3, z. B. ``"13335"``). ``asn_org`` wird seit F0 mit dem
Betreibernamen aus Spalte 4 der iptoasn-asn-CSV durchgereicht (z. B. ``"CLOUDFLARENET"``)
-- ROH, ohne Kosmetik (kein Trimming/Title-Case): ehrlich anzeigen, was die DB sagt. Ist
der Name leer (trailing comma / fehlend) oder gibt es keinen ASN-Treffer, bleibt
``asn_org`` ``None`` (kein erfundener Wert, S3).

KEIN stiller Leer-Fallback wie ``modules.vendor._load_db``: fehlt eine CSV BEIM LADEN,
ist das ein echter Konfigurationsfehler -> ``ResolverDataMissing``. Ein nicht gefundener
Eintrag im Lookup ist dagegen ein gueltiger Leer-Zustand (Feld ``None``).

Performance: die vier CSVs werden EINMAL im Konstruktor in nach ``start_int`` sortierte
Listen ``(start_int, end_int, wert)`` geladen (int-Grenzen vorberechnet). ``lookup`` ist
reine ``bisect``-Suche, kein Re-Read pro Aufruf.
"""

import bisect
import ipaddress
from pathlib import Path

from domain.resolver import GeoAsnRecord
from infrastructure.resolver.errors import ResolverDataMissing

# Default-Datenverzeichnis: ``backend/data`` relativ zu dieser Modul-Datei
# (geo_asn.py -> resolver -> infrastructure -> backend), Muster wie ``modules.vendor``
# oui.json relativ ueber ``__file__`` aufloest -- aber sauber per ``pathlib`` und ohne
# ``modules``-Import.
_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"

_COUNTRY_IPV4 = "asn-country-ipv4.csv"
_COUNTRY_IPV6 = "asn-country-ipv6.csv"
_ASN_IPV4 = "iptoasn-asn-ipv4.csv"
_ASN_IPV6 = "iptoasn-asn-ipv6.csv"


def _ip_int(literal: str) -> int:
    """Wandelt ein IP-Literal (v4 oder v6) in seine ganzzahlige Darstellung."""
    return int(ipaddress.ip_address(literal))


def _parse_country_csv(text: str) -> list[tuple[int, int, str]]:
    """asn-country-CSV-Text -> nach ``start_int`` sortierte ``(start,end,country)``-Liste.

    Spalten ``ip_range_start,ip_range_end,country_code`` ohne Kopfzeile. Leere Zeilen
    werden uebersprungen; die Range-Grenzen werden hier EINMAL in ``int`` vorberechnet.
    """
    rows: list[tuple[int, int, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        start, end, country = line.split(",", 2)
        rows.append((_ip_int(start), _ip_int(end), country))
    rows.sort(key=lambda row: row[0])
    return rows


def _parse_asn_csv(text: str) -> list[tuple[int, int, str, str]]:
    """iptoasn-asn-CSV-Text -> nach ``start_int`` sortierte ``(start,end,asn,name)``-Liste.

    Spalten ``ip_range_start,ip_range_end,asn,asn_name`` ohne Kopfzeile. Seit F0 wird
    NEBEN der ASN-NUMMER (Spalte 3) auch der Betreibername ``asn_name`` (Spalte 4)
    behalten und als viertes Tupel-Element gefuehrt. ``asn_name`` kann selbst Kommata
    enthalten (z. B. ``"GOOGLE, LLC"``) -- ``split(",", 3)`` mit ``maxsplit=3`` faengt das
    ab, der Rest der Zeile landet vollstaendig im Namen. Ein leerer Name (trailing comma /
    fehlend) bleibt hier ein leerer String; die Umsetzung zu ``None`` macht erst der
    Lookup, NICHT der Parser.
    """
    rows: list[tuple[int, int, str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        start, end, asn, asn_name = line.split(",", 3)
        rows.append((_ip_int(start), _ip_int(end), asn, asn_name))
    rows.sort(key=lambda row: row[0])
    return rows


def _find(sorted_rows: list[tuple[int, int, str]], ip_int: int) -> str | None:
    """Binaersuche: Wert der Range mit ``start <= ip_int <= end``, sonst ``None``.

    Die Liste ist nach ``start_int`` aufsteigend und ueberlappungsfrei. ``bisect_right``
    auf den ``start``-Grenzen liefert den ersten Eintrag MIT ``start > ip_int``; der
    Kandidat ist der direkt davor. Dessen ``end`` entscheidet ueber den Treffer.
    """
    idx = bisect.bisect_right(sorted_rows, (ip_int, _SENTINEL_HIGH, "")) - 1
    if idx < 0:
        return None
    start_int, end_int, value = sorted_rows[idx]
    if start_int <= ip_int <= end_int:
        return value
    return None


def _find_asn(sorted_rows: list[tuple[int, int, str, str]], ip_int: int) -> tuple[str, str] | None:
    """Wie ``_find``, aber fuer die 4-Tupel-ASN-Rows -> ``(asn_nummer, asn_name)``.

    Eigene schmale Lookup-Funktion (statt ``_find`` generisch aufzuweichen), damit der
    country-Pfad ueber 3-Tupel unveraendert und mypy-sauber bleibt. Identische
    ``bisect``-Logik: nach ``start_int`` sortiert, Treffer wenn ``start <= ip <= end``.
    Liefert bei Treffer das Paar ``(asn, asn_name)`` -- der ROHE Name, ohne Kosmetik;
    die Leer-zu-``None``-Umsetzung macht erst der Aufrufer (``lookup``). Kein Treffer ->
    ``None``.
    """
    idx = bisect.bisect_right(sorted_rows, (ip_int, _SENTINEL_HIGH, "", "")) - 1
    if idx < 0:
        return None
    start_int, end_int, asn, asn_name = sorted_rows[idx]
    if start_int <= ip_int <= end_int:
        return asn, asn_name
    return None


# Obergrenze fuer das Tupel-Vergleichs-Probe in ``_find``: groesser als jede moegliche
# IPv6-Adresse, damit ``bisect_right`` rein ueber ``start_int`` entscheidet.
_SENTINEL_HIGH = (1 << 128) + 1


class CsvGeoAsnDb:
    """Erfuellt ``GeoAsnDbPort`` strukturell -- synchroner CSV-Lookup, einmal geladen.

    Der Konstruktor laedt die vier CSVs aus ``data_dir`` (Default ``backend/data``,
    im Test injizierbar) EINMAL in vier sortierte Listen. Fehlt eine Datei ->
    ``ResolverDataMissing`` (kein stiller Leer-Fallback).
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        base = data_dir if data_dir is not None else _DEFAULT_DATA_DIR
        self._country_v4 = _parse_country_csv(_read(base / _COUNTRY_IPV4))
        self._country_v6 = _parse_country_csv(_read(base / _COUNTRY_IPV6))
        self._asn_v4 = _parse_asn_csv(_read(base / _ASN_IPV4))
        self._asn_v6 = _parse_asn_csv(_read(base / _ASN_IPV6))

    def lookup(self, ip: str) -> GeoAsnRecord:
        """Liefert ``GeoAsnRecord`` zur ``ip`` (leer wenn nichts/ungueltig).

        Reiner lokaler ``bisect``-Lookup. Ungueltige ``ip`` -> leerer Record (wirft
        NICHT). IPv4 nutzt die v4-, IPv6 die v6-Listen. Pro Familie kein Treffer ->
        das jeweilige Feld ``None``. ``asn`` UND ``asn_org`` stammen aus demselben
        ASN-Treffer: ``asn`` = die Nummer, ``asn_org`` = der ROHE Name aus Spalte 4 --
        ODER ``None``, falls kein ASN-Treffer oder der Name leer ist (kein erfundener
        Wert, S3).
        """
        try:
            ip_int = int(ipaddress.ip_address(ip))
        except ValueError:
            return GeoAsnRecord()

        is_v6 = ipaddress.ip_address(ip).version == 6
        country_rows = self._country_v6 if is_v6 else self._country_v4
        asn_rows = self._asn_v6 if is_v6 else self._asn_v4

        asn_hit = _find_asn(asn_rows, ip_int)
        if asn_hit is None:
            asn, asn_org = None, None
        else:
            asn, asn_name = asn_hit
            # Leerer Name (trailing comma / fehlend) -> ehrlich ``None``, kein "".
            asn_org = asn_name or None

        return GeoAsnRecord(
            country=_find(country_rows, ip_int),
            asn=asn,
            asn_org=asn_org,
        )


def _read(path: Path) -> str:
    """Liest eine CSV; fehlt sie, ist das ein Konfigurationsfehler -> Exception."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ResolverDataMissing(str(path)) from exc
