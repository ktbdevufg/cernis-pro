"""Tests der reinen export-Domaene (Block 1): to_json/to_csv/build_pdf_model + Helfer.

Kern der Behauptungen (rein, deterministisch, mutationsproben-tauglich):

* ``to_json`` -- verlustfrei strukturiert, sortierte Keys, Listen-Reihenfolge stabil.
* ``to_csv`` -- DEFINIERTE Spalten-Reihenfolge + Header, ports/tags zusammengefasst,
  Escaping von Komma/Anfuehrungszeichen via csv-Modul.
* ``build_pdf_model`` -- richtige columns/rows + Kopf-Felder.
* ``format_ports``/``format_tags`` -- reine Zusammenfassung.

Edge-Cases: leerer Scan (0 Hosts), Host mit leeren Feldern, Sonderzeichen. Mutationsproben:
die Spalten-Reihenfolge in to_csv / build_pdf_model ist Vertrag (Vertauschung -> rot).
"""

import csv
import io
import json

from domain.export import (
    ExportableHost,
    ExportablePort,
    ExportableScan,
    build_pdf_model,
    format_ports,
    format_tags,
    to_csv,
    to_json,
)

# ── Test-Daten ───────────────────────────────────────────────────────────────


def _full_host() -> ExportableHost:
    """Ein Host mit gefuellten Kern-/Listen-Feldern (fuer die Verlustfreiheits-Pruefung)."""
    return ExportableHost(
        ip="192.168.1.10",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Acme Corp",
        hostname="server.local",
        rtt_ms=1.5,
        os_guess="Linux",
        os_accuracy=95,
        category="server",
        label="Mein Server",
        tags=("prod", "web"),
        source="ping",
        ports=(
            ExportablePort(port=22, protocol="tcp", service="ssh"),
            ExportablePort(port=80, protocol="tcp", service="http"),
            ExportablePort(port=443, protocol="tcp", service="https"),
        ),
        mdns_services=("_http._tcp", "_ssh._tcp"),
        ssdp_services=("Linux/3.0 UPnP/1.0",),
    )


def _scan(*hosts: ExportableHost) -> ExportableScan:
    return ExportableScan(
        scan_id=42,
        cidr="192.168.1.0/24",
        host_count=len(hosts),
        scanned_at="2026-06-11T12:00:00",
        hosts=hosts,
    )


# ── format_ports / format_tags ───────────────────────────────────────────────


def test_format_ports_joins_port_and_protocol() -> None:
    ports = (
        ExportablePort(port=22, protocol="tcp", service="ssh"),
        ExportablePort(port=80, protocol="tcp", service="http"),
    )
    assert format_ports(ports) == "22/tcp,80/tcp"


def test_format_ports_empty() -> None:
    assert format_ports(()) == ""


def test_format_ports_preserves_input_order() -> None:
    # Reihenfolge ist die der Eingabe -- KEIN Umsortieren (reproduzierbar zur Scan-Ordnung).
    ports = (
        ExportablePort(port=443, protocol="tcp"),
        ExportablePort(port=22, protocol="tcp"),
    )
    assert format_ports(ports) == "443/tcp,22/tcp"


def test_format_tags_joins_with_semicolon() -> None:
    assert format_tags(("a", "b")) == "a;b"


def test_format_tags_empty() -> None:
    assert format_tags(()) == ""


# ── to_json (verlustfrei, deterministisch, sortierte Keys) ────────────────────


def test_to_json_is_lossless() -> None:
    """Alle Host-Felder + verschachtelte Listen erscheinen verlustfrei im JSON."""
    host = _full_host()
    payload = json.loads(to_json(_scan(host)))

    assert payload["scan_id"] == 42
    assert payload["cidr"] == "192.168.1.0/24"
    assert payload["host_count"] == 1
    assert payload["scanned_at"] == "2026-06-11T12:00:00"
    assert len(payload["hosts"]) == 1

    h = payload["hosts"][0]
    assert h["ip"] == "192.168.1.10"
    assert h["mac"] == "aa:bb:cc:dd:ee:ff"
    assert h["vendor"] == "Acme Corp"
    assert h["hostname"] == "server.local"
    assert h["rtt_ms"] == 1.5
    assert h["os_guess"] == "Linux"
    assert h["os_accuracy"] == 95
    assert h["category"] == "server"
    assert h["label"] == "Mein Server"
    assert h["tags"] == ["prod", "web"]
    assert h["source"] == "ping"
    # Ports verschachtelt als Objekt-Liste (verlustfrei inkl. Servicename).
    assert h["ports"] == [
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        {"port": 80, "protocol": "tcp", "service": "http"},
        {"port": 443, "protocol": "tcp", "service": "https"},
    ]
    assert h["mdns_services"] == ["_http._tcp", "_ssh._tcp"]
    assert h["ssdp_services"] == ["Linux/3.0 UPnP/1.0"]


def test_to_json_keys_are_sorted() -> None:
    """``sort_keys`` -> stabile Key-Reihenfolge (Top-Level alphabetisch)."""
    text = to_json(_scan(_full_host()))
    payload = json.loads(text)
    assert list(payload.keys()) == sorted(payload.keys())
    # Auch innerhalb eines Hosts sind die Keys sortiert.
    host_keys = list(payload["hosts"][0].keys())
    assert host_keys == sorted(host_keys)


def test_to_json_is_deterministic() -> None:
    """Gleiche Eingabe -> exakt gleicher String (reproduzierbar)."""
    scan = _scan(_full_host())
    assert to_json(scan) == to_json(scan)


def test_to_json_empty_scan() -> None:
    payload = json.loads(to_json(_scan()))
    assert payload["host_count"] == 0
    assert payload["hosts"] == []


def test_to_json_keeps_non_ascii_readable() -> None:
    """``ensure_ascii=False`` -> Sonderzeichen bleiben echt (kein \\uXXXX)."""
    host = ExportableHost(ip="10.0.0.1", label="Büro-Drucker")
    text = to_json(_scan(host))
    assert "Büro-Drucker" in text
    assert "\\u" not in text


# ── to_csv (Spalten-Reihenfolge, Header, Zusammenfassung, Escaping) ───────────

_EXPECTED_CSV_HEADER = [
    "ip",
    "mac",
    "vendor",
    "hostname",
    "os_guess",
    "category",
    "label",
    "open_ports",
    "tags",
    "source",
]


def _parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def test_to_csv_header_is_defined_order() -> None:
    """Die Header-Zeile ist die DEFINIERTE Spalten-Reihenfolge (Mutationsprobe-Anker)."""
    rows = _parse_csv(to_csv(_scan(_full_host())))
    assert rows[0] == _EXPECTED_CSV_HEADER


def test_to_csv_row_values_in_column_order() -> None:
    """Eine Host-Zeile traegt die Werte exakt in der Spalten-Reihenfolge."""
    rows = _parse_csv(to_csv(_scan(_full_host())))
    assert rows[1] == [
        "192.168.1.10",
        "aa:bb:cc:dd:ee:ff",
        "Acme Corp",
        "server.local",
        "Linux",
        "server",
        "Mein Server",
        "22/tcp,80/tcp,443/tcp",
        "prod;web",
        "ping",
    ]


def test_to_csv_column_order_is_contract() -> None:
    """MUTATIONSPROBE: vertauschte Erwartungs-Spalten muessen rot sein.

    Belegt, dass die Spalten-Reihenfolge ein bindender Vertrag ist: eine vertauschte
    Header-Erwartung (ip/mac getauscht) darf NICHT durchgehen.
    """
    rows = _parse_csv(to_csv(_scan(_full_host())))
    swapped_header = ["mac", "ip", *_EXPECTED_CSV_HEADER[2:]]
    assert rows[0] != swapped_header


def test_to_csv_escapes_comma_and_quotes() -> None:
    """Sonderzeichen (Komma, Anfuehrungszeichen) werden vom csv-Modul korrekt escaped."""
    host = ExportableHost(ip="10.0.0.5", label='Server, "Haupt"', vendor="A,B Inc")
    text = to_csv(_scan(host))
    # Round-trip: der Parser liest die Werte exakt zurueck (korrektes Quoting).
    rows = _parse_csv(text)
    label_idx = _EXPECTED_CSV_HEADER.index("label")
    vendor_idx = _EXPECTED_CSV_HEADER.index("vendor")
    assert rows[1][label_idx] == 'Server, "Haupt"'
    assert rows[1][vendor_idx] == "A,B Inc"


def test_to_csv_empty_scan_has_only_header() -> None:
    rows = _parse_csv(to_csv(_scan()))
    assert rows == [_EXPECTED_CSV_HEADER]


def test_to_csv_host_with_empty_fields() -> None:
    """Ein Host mit leeren Feldern -> leere Zellen (keine None/Platzhalter)."""
    host = ExportableHost(ip="10.0.0.9")
    rows = _parse_csv(to_csv(_scan(host)))
    assert rows[1][0] == "10.0.0.9"
    # open_ports und tags leer -> ""
    assert rows[1][_EXPECTED_CSV_HEADER.index("open_ports")] == ""
    assert rows[1][_EXPECTED_CSV_HEADER.index("tags")] == ""


# ── build_pdf_model (columns/rows/Kopf-Felder) ────────────────────────────────

_EXPECTED_PDF_COLUMNS = (
    "ip",
    "mac",
    "vendor",
    "hostname",
    "os_guess",
    "category",
    "open_ports",
)


def test_build_pdf_model_header_fields() -> None:
    model = build_pdf_model(_scan(_full_host()))
    assert model.title == "CERNIS PRO — Scan-Bericht"
    assert model.scanned_at == "2026-06-11T12:00:00"
    assert model.cidr == "192.168.1.0/24"
    assert model.host_count == 1


def test_build_pdf_model_columns_are_defined_order() -> None:
    model = build_pdf_model(_scan(_full_host()))
    assert model.columns == _EXPECTED_PDF_COLUMNS


def test_build_pdf_model_rows_in_column_order() -> None:
    model = build_pdf_model(_scan(_full_host()))
    assert model.rows == (
        (
            "192.168.1.10",
            "aa:bb:cc:dd:ee:ff",
            "Acme Corp",
            "server.local",
            "Linux",
            "server",
            "22/tcp,80/tcp,443/tcp",
        ),
    )


def test_build_pdf_model_columns_are_contract() -> None:
    """MUTATIONSPROBE: eine entfernte/vertauschte Spalte muss rot sein.

    Belegt, dass die PDF-Spaltenwahl ein bindender Vertrag ist: eine um eine Spalte gekuerzte
    Erwartung darf NICHT mit den echten columns uebereinstimmen.
    """
    model = build_pdf_model(_scan(_full_host()))
    without_open_ports = _EXPECTED_PDF_COLUMNS[:-1]
    assert model.columns != without_open_ports


def test_build_pdf_model_empty_scan() -> None:
    model = build_pdf_model(_scan())
    assert model.host_count == 0
    assert model.rows == ()
    # Der Kopf bleibt vollstaendig (gueltiger, druckbarer Bericht ohne Hosts).
    assert model.columns == _EXPECTED_PDF_COLUMNS
