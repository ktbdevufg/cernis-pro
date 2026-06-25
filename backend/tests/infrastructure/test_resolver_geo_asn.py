"""Tests des resolver-GeoAsnDb-Adapters -- kleine Inline-CSVs, NICHT die Riesen-DBs.

Bewusst OHNE die echten CC0/PDDL-Riesen-CSVs (zu gross/langsam): je Familie 3-5 Zeilen
werden inline in Temp-Dateien (``tmp_path``-Fixture) geschrieben und der Adapter auf
dieses Temp-Verzeichnis gezeigt (Konstruktor-Injektion ``data_dir``). Geprueft werden der
Lookup-Vertrag (country + ASN-Nummer + ``asn_org`` aus Spalte 4, ``None`` nur bei keinem
Treffer / leerem Namen), die strenge
Leer-Toleranz (kein Treffer / ungueltige IP -> leerer Record, kein Wurf), der v6-Pfad,
der echte Konfigurationsfehler (fehlende CSV -> ``ResolverDataMissing``) sowie die
``bisect``-Randfaelle der reinen Helfer.
"""

from pathlib import Path

import pytest

from domain.resolver import GeoAsnRecord
from infrastructure.resolver.errors import ResolverDataMissing
from infrastructure.resolver.geo_asn import (
    CsvGeoAsnDb,
    _find,
    _find_asn,
    _parse_asn_csv,
    _parse_country_csv,
)

# ── Inline-Mini-CSVs (3-5 Zeilen je Familie) ──────────────────────────────────

_COUNTRY_V4 = (
    "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n8.8.8.0,8.8.8.255,US\n10.0.0.0,10.255.255.255,DE\n"
)
_COUNTRY_V6 = (
    "2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n"
    "2001:208::,2001:208:ffff:ffff:ffff:ffff:ffff:ffff,SG\n"
)
# asn_name (Spalte 4) enthaelt bewusst ein Komma -> prueft split(",", 3).
# Letzte Zeile hat einen LEEREN Namen (trailing comma) -> asn_org muss None werden.
_ASN_V4 = (
    "1.0.0.0,1.0.0.255,13335,CLOUDFLARENET\n"
    "8.8.8.0,8.8.8.255,15169,GOOGLE, LLC\n"
    "10.0.0.0,10.255.255.255,64512,PRIVATE-AS\n"
    "203.0.113.0,203.0.113.255,65000,\n"
)
_ASN_V6 = (
    "2001:200::,2001:200:8ff:ffff:ffff:ffff:ffff:ffff,2500,WIDE-BB WIDE Project\n"
    "2001:208::,2001:208:ffff:ffff:ffff:ffff:ffff:ffff,4788,TMNET-AS-AP\n"
)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Schreibt die vier Mini-CSVs in ein Temp-Verzeichnis und gibt es zurueck."""
    (tmp_path / "asn-country-ipv4.csv").write_text(_COUNTRY_V4, encoding="utf-8")
    (tmp_path / "asn-country-ipv6.csv").write_text(_COUNTRY_V6, encoding="utf-8")
    (tmp_path / "iptoasn-asn-ipv4.csv").write_text(_ASN_V4, encoding="utf-8")
    (tmp_path / "iptoasn-asn-ipv6.csv").write_text(_ASN_V6, encoding="utf-8")
    return tmp_path


# ── Adapter-Lookup ────────────────────────────────────────────────────────────


def test_ip_in_both_ranges_fills_country_asn_and_org(data_dir: Path) -> None:
    """IP in Land- UND ASN-Range -> country, asn UND asn_org (Spalte 4) gesetzt."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    record = db.lookup("1.0.0.1")
    assert record.country == "AU"
    assert record.asn == "13335"
    assert record.asn_org == "CLOUDFLARENET"


def test_asn_name_with_comma_is_kept_whole(data_dir: Path) -> None:
    """asn_name (Spalte 4) mit Komma bleibt VOLLSTAENDIG -- ASN-Nummer unverfaelscht."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    record = db.lookup("8.8.8.8")
    # "GOOGLE, LLC" darf die ASN-Nummer nicht verfaelschen UND muss komplett im Namen sein.
    assert record.asn == "15169"
    assert record.asn_org == "GOOGLE, LLC"


def test_empty_asn_name_yields_none_org(data_dir: Path) -> None:
    """ASN-Treffer mit leerem Namen (trailing comma) -> asn gesetzt, asn_org None (S3)."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    record = db.lookup("203.0.113.7")
    assert record.asn == "65000"
    assert record.asn_org is None


def test_ip_only_in_country_range_leaves_asn_none(data_dir: Path) -> None:
    """IP nur in einer Land-Range, nicht in einer ASN-Range -> asn None."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    # 1.0.1.0-1.0.3.255 hat Land (CN), aber keine ASN-Range deckt es ab.
    record = db.lookup("1.0.2.42")
    assert record.country == "CN"
    assert record.asn is None
    assert record.asn_org is None


def test_ip_in_no_range_returns_empty_record(data_dir: Path) -> None:
    """IP in keinem Range -> leerer GeoAsnRecord (alle None)."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    assert db.lookup("198.51.100.1") == GeoAsnRecord()


def test_ipv6_uses_v6_lists(data_dir: Path) -> None:
    """IPv6-IP nutzt die v6-Listen (country + asn aus den v6-CSVs)."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    record = db.lookup("2001:200::1")
    assert record.country == "JP"
    assert record.asn == "2500"
    assert record.asn_org == "WIDE-BB WIDE Project"


def test_invalid_ip_returns_empty_record_without_raising(data_dir: Path) -> None:
    """Ungueltige IP -> leerer GeoAsnRecord, KEIN Wurf."""
    db = CsvGeoAsnDb(data_dir=data_dir)
    assert db.lookup("nope") == GeoAsnRecord()


def test_missing_csv_raises_resolver_data_missing(data_dir: Path) -> None:
    """Fehlt eine CSV beim Laden -> ResolverDataMissing im Konstruktor."""
    (data_dir / "iptoasn-asn-ipv6.csv").unlink()
    with pytest.raises(ResolverDataMissing) as excinfo:
        CsvGeoAsnDb(data_dir=data_dir)
    assert "iptoasn-asn-ipv6.csv" in excinfo.value.path


# ── reine Helfer: _parse_* + _find/bisect-Randfaelle ──────────────────────────


def test_parse_country_csv_sorts_and_precomputes_ints() -> None:
    """_parse_country_csv liefert nach start_int sortierte int-Tripel."""
    rows = _parse_country_csv("8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,AU\n")
    assert rows == [
        (int.from_bytes(b"\x01\x00\x00\x00", "big"), 0x010000FF, "AU"),
        (0x08080800, 0x080808FF, "US"),
    ]


def test_parse_asn_csv_keeps_number_and_name() -> None:
    """_parse_asn_csv behaelt ASN-Nummer (Spalte 3) UND Name (Spalte 4) als 4-Tupel.

    Der Name mit Komma ("GOOGLE, LLC") muss vollstaendig erhalten bleiben (split mit
    maxsplit=3); ein leerer Name (trailing comma) bleibt im Parser ein leerer String.
    """
    rows = _parse_asn_csv("8.8.8.0,8.8.8.255,15169,GOOGLE, LLC\n203.0.113.0,203.0.113.255,65000,\n")
    assert rows == [
        (0x08080800, 0x080808FF, "15169", "GOOGLE, LLC"),
        (0xCB007100, 0xCB0071FF, "65000", ""),
    ]


def test_find_asn_returns_number_and_name_pair() -> None:
    """_find_asn liefert das Paar (asn, asn_name) bei Treffer, None sonst -- roh."""
    rows = _parse_asn_csv("1.0.0.0,1.0.0.255,13335,CLOUDFLARENET\n")
    assert _find_asn(rows, 0x01000000) == ("13335", "CLOUDFLARENET")
    assert _find_asn(rows, 0x010000FF) == ("13335", "CLOUDFLARENET")
    assert _find_asn(rows, 0x01000100) is None
    assert _find_asn([], 0x08080808) is None


def test_find_exact_start_and_end_boundaries() -> None:
    """_find trifft genau bei start und genau bei end (inklusiv)."""
    rows = _parse_country_csv("1.0.0.0,1.0.0.255,AU\n")
    start = 0x01000000
    end = 0x010000FF
    assert _find(rows, start) == "AU"
    assert _find(rows, end) == "AU"


def test_find_just_outside_boundaries_misses() -> None:
    """_find verfehlt knapp unter start und knapp ueber end."""
    rows = _parse_country_csv("1.0.1.0,1.0.1.255,CN\n")
    start = 0x01000100
    end = 0x010001FF
    assert _find(rows, start - 1) is None
    assert _find(rows, end + 1) is None


def test_find_in_gap_between_ranges_misses() -> None:
    """_find verfehlt in der Luecke zwischen zwei nicht benachbarten Ranges."""
    rows = _parse_country_csv("1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n")
    assert _find(rows, 0x04040404) is None


def test_find_on_empty_list_returns_none() -> None:
    """_find auf leerer Liste -> None (kein IndexError)."""
    assert _find([], 0x08080808) is None
