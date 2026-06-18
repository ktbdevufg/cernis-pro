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
from datetime import datetime

from domain.export import (
    ExportableAnalysis,
    ExportableFinding,
    ExportableHost,
    ExportableLoggingEvent,
    ExportableLoggingReport,
    ExportableLoggingRtt,
    ExportablePort,
    ExportableScan,
    analysis_to_csv,
    analysis_to_json,
    build_analysis_pdf_model,
    build_logging_report_pdf_model,
    build_pdf_model,
    format_ports,
    format_tags,
    logging_report_to_csv,
    logging_report_to_json,
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
    # Kopf jetzt als generische (Label, Wert)-Paare (ADR 0015, Block 2: PdfReportModel
    # generalisiert) -- semantisch identisch zu vorher (Scan-Zeitpunkt/Netz/Anzahl).
    assert model.meta == (
        ("Scan-Zeitpunkt", "2026-06-11T12:00:00"),
        ("Gescanntes Netz", "192.168.1.0/24"),
        ("Geräteanzahl", "1"),
    )


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
    # Geraeteanzahl 0 steht im Kopf-Paar (generalisiertes Modell).
    assert model.meta[2] == ("Geräteanzahl", "0")
    assert model.rows == ()
    # Der Kopf bleibt vollstaendig (gueltiger, druckbarer Bericht ohne Hosts).
    assert model.columns == _EXPECTED_PDF_COLUMNS


# ── Block 2: Analyse-Befunde -> CSV/JSON/PDF (ADR 0015, Block 2) ───────────────
#
# analysis_to_json (verlustfrei, sortierte Keys, deterministisch), analysis_to_csv
# (Spalten-Reihenfolge severity/title/subject/detail/rule_id/help_kind/help_url, Header,
# Escaping, Befund-Reihenfolge beibehalten), build_analysis_pdf_model (columns/rows/Kopf inkl.
# generated_at/finding_count). Edge: leere Analyse, Sonderzeichen. Mutationsproben: csv-
# Spaltenreihenfolge vertauschen -> rot; eine pdf-Spalte entfernen -> rot.


def _finding(
    rule_id: str = "remote_access_port",
    severity: str = "notable",
    title: str = "Verbindung zu einem Fernzugriffs-Port",
    detail: str = "Verbindung zu 1.2.3.4:5900 nutzt einen typischen Fernzugriffs-Port (5900).",
    subject: str = "1.2.3.4:5900",
    help_kind: str = "remote_access_port",
    help_url: str = "https://help.example/remote",
) -> ExportableFinding:
    return ExportableFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        subject=subject,
        help_kind=help_kind,
        help_url=help_url,
    )


def _analysis(*findings: ExportableFinding) -> ExportableAnalysis:
    return ExportableAnalysis(
        generated_at="2026-06-11T12:00:00+00:00",
        findings=findings,
        finding_count=len(findings),
    )


# ── analysis_to_json (verlustfrei, deterministisch, sortierte Keys) ───────────


def test_analysis_to_json_is_lossless() -> None:
    """Alle Befund-Felder + Kopf erscheinen verlustfrei im JSON."""
    payload = json.loads(analysis_to_json(_analysis(_finding())))

    assert payload["generated_at"] == "2026-06-11T12:00:00+00:00"
    assert payload["finding_count"] == 1
    assert len(payload["findings"]) == 1

    f = payload["findings"][0]
    assert f["rule_id"] == "remote_access_port"
    assert f["severity"] == "notable"
    assert f["title"] == "Verbindung zu einem Fernzugriffs-Port"
    assert f["detail"].startswith("Verbindung zu 1.2.3.4:5900")
    assert f["subject"] == "1.2.3.4:5900"
    assert f["help_kind"] == "remote_access_port"
    assert f["help_url"] == "https://help.example/remote"


def test_analysis_to_json_keys_are_sorted() -> None:
    payload = json.loads(analysis_to_json(_analysis(_finding())))
    assert list(payload.keys()) == sorted(payload.keys())
    finding_keys = list(payload["findings"][0].keys())
    assert finding_keys == sorted(finding_keys)


def test_analysis_to_json_is_deterministic() -> None:
    analysis = _analysis(_finding(), _finding(subject="5.6.7.8:22"))
    assert analysis_to_json(analysis) == analysis_to_json(analysis)


def test_analysis_to_json_empty() -> None:
    payload = json.loads(analysis_to_json(_analysis()))
    assert payload["finding_count"] == 0
    assert payload["findings"] == []


def test_analysis_to_json_keeps_non_ascii_readable() -> None:
    text = analysis_to_json(_analysis(_finding(detail="Prozess läuft aus /tmp - auffällig.")))
    assert "läuft aus /tmp - auffällig" in text
    assert "\\u" not in text


def test_analysis_to_json_keeps_finding_order() -> None:
    """Die Befund-Reihenfolge bleibt die der Eingabe (keine Sortierung der Liste)."""
    payload = json.loads(analysis_to_json(_analysis(_finding(subject="b"), _finding(subject="a"))))
    assert [f["subject"] for f in payload["findings"]] == ["b", "a"]


# ── analysis_to_csv (Spalten-Reihenfolge, Header, Escaping, Befund-Reihenfolge) ─

_EXPECTED_ANALYSIS_CSV_HEADER = [
    "severity",
    "title",
    "subject",
    "detail",
    "rule_id",
    "help_kind",
    "help_url",
]


def test_analysis_to_csv_header_is_defined_order() -> None:
    rows = _parse_csv(analysis_to_csv(_analysis(_finding())))
    assert rows[0] == _EXPECTED_ANALYSIS_CSV_HEADER


def test_analysis_to_csv_row_values_in_column_order() -> None:
    rows = _parse_csv(analysis_to_csv(_analysis(_finding())))
    assert rows[1] == [
        "notable",
        "Verbindung zu einem Fernzugriffs-Port",
        "1.2.3.4:5900",
        "Verbindung zu 1.2.3.4:5900 nutzt einen typischen Fernzugriffs-Port (5900).",
        "remote_access_port",
        "remote_access_port",
        "https://help.example/remote",
    ]


def test_analysis_to_csv_column_order_is_contract() -> None:
    """MUTATIONSPROBE: vertauschte Erwartungs-Spalten muessen rot sein.

    severity/title getauscht darf NICHT mit dem echten Header uebereinstimmen.
    """
    rows = _parse_csv(analysis_to_csv(_analysis(_finding())))
    swapped_header = ["title", "severity", *_EXPECTED_ANALYSIS_CSV_HEADER[2:]]
    assert rows[0] != swapped_header


def test_analysis_to_csv_escapes_comma_and_quotes() -> None:
    """Sonderzeichen (Komma, Anfuehrungszeichen) werden vom csv-Modul korrekt escaped."""
    finding = _finding(detail='Prozess "x", aus /tmp', subject="pid 7, host")
    rows = _parse_csv(analysis_to_csv(_analysis(finding)))
    detail_idx = _EXPECTED_ANALYSIS_CSV_HEADER.index("detail")
    subject_idx = _EXPECTED_ANALYSIS_CSV_HEADER.index("subject")
    assert rows[1][detail_idx] == 'Prozess "x", aus /tmp'
    assert rows[1][subject_idx] == "pid 7, host"


def test_analysis_to_csv_empty_has_only_header() -> None:
    rows = _parse_csv(analysis_to_csv(_analysis()))
    assert rows == [_EXPECTED_ANALYSIS_CSV_HEADER]


def test_analysis_to_csv_keeps_finding_order() -> None:
    rows = _parse_csv(analysis_to_csv(_analysis(_finding(subject="b"), _finding(subject="a"))))
    subject_idx = _EXPECTED_ANALYSIS_CSV_HEADER.index("subject")
    assert [rows[1][subject_idx], rows[2][subject_idx]] == ["b", "a"]


# ── build_analysis_pdf_model (columns/rows/Kopf inkl. generated_at/finding_count) ─

_EXPECTED_ANALYSIS_PDF_COLUMNS = (
    "severity",
    "title",
    "subject",
    "detail",
)


def test_build_analysis_pdf_model_header_fields() -> None:
    model = build_analysis_pdf_model(_analysis(_finding(), _finding(subject="x")))
    assert model.title == "CERNIS PRO — Analyse-Bericht"
    assert model.meta == (
        ("Erzeugt am", "2026-06-11T12:00:00+00:00"),
        ("Anzahl Befunde", "2"),
    )


def test_build_analysis_pdf_model_columns_are_defined_order() -> None:
    model = build_analysis_pdf_model(_analysis(_finding()))
    assert model.columns == _EXPECTED_ANALYSIS_PDF_COLUMNS


def test_build_analysis_pdf_model_rows_in_column_order() -> None:
    model = build_analysis_pdf_model(_analysis(_finding()))
    assert model.rows == (
        (
            "notable",
            "Verbindung zu einem Fernzugriffs-Port",
            "1.2.3.4:5900",
            "Verbindung zu 1.2.3.4:5900 nutzt einen typischen Fernzugriffs-Port (5900).",
        ),
    )


def test_build_analysis_pdf_model_columns_are_contract() -> None:
    """MUTATIONSPROBE: eine entfernte Spalte muss rot sein."""
    model = build_analysis_pdf_model(_analysis(_finding()))
    without_detail = _EXPECTED_ANALYSIS_PDF_COLUMNS[:-1]
    assert model.columns != without_detail


def test_build_analysis_pdf_model_excludes_technical_columns() -> None:
    """rule_id/help_kind/help_url sind BEWUSST nicht in der PDF-Tabelle (nur CSV/JSON)."""
    model = build_analysis_pdf_model(_analysis(_finding()))
    assert "rule_id" not in model.columns
    assert "help_kind" not in model.columns
    assert "help_url" not in model.columns


def test_build_analysis_pdf_model_truncates_long_detail() -> None:
    """Ein ueberlanges detail wird fuer die PDF-Zelle gekuerzt (CSV/JSON bleiben voll)."""
    long_detail = "x" * 300
    model = build_analysis_pdf_model(_analysis(_finding(detail=long_detail)))
    cell = model.rows[0][3]
    assert len(cell) == 120
    assert cell.endswith("…")
    # CSV fuehrt das volle detail (kein Kuerzen dort).
    csv_rows = _parse_csv(analysis_to_csv(_analysis(_finding(detail=long_detail))))
    assert csv_rows[1][_EXPECTED_ANALYSIS_CSV_HEADER.index("detail")] == long_detail


def test_build_analysis_pdf_model_empty() -> None:
    model = build_analysis_pdf_model(_analysis())
    assert model.meta[1] == ("Anzahl Befunde", "0")
    assert model.rows == ()
    assert model.columns == _EXPECTED_ANALYSIS_PDF_COLUMNS


# ── Block 3: Logging-Report -> CSV/JSON/PDF (Reporting Schnitt 1a) ─────────────
#
# logging_report_to_json (verlustfrei: Kopf + ALLE rtt_points + ALLE events, sortierte Keys,
# roher ts + lesbarer ts_iso), logging_report_to_csv (NUR die RTT-Reihe, Spalten ts_iso/rtt_ms/
# loss_pct/alive, alive als true/false), build_logging_report_pdf_model (SLA-Kopf-meta-Paare,
# Ereignis-Tabelle, uptime None -> "keine Auswertung", Zahlenformat f"{x:.1f}"). Mutationsproben:
# csv-Spalten + pdf-Spalten sind Vertrag.
#
# Die ts->ISO-Darstellung ist zeitzonen-abhaengig (datetime.fromtimestamp, lokal) -- darum
# vergleichen die Tests gegen ``datetime.fromtimestamp(ts).isoformat()`` (dieselbe Rechnung),
# NICHT gegen einen hartkodierten String, damit sie auf jeder Test-Maschine gruen sind.

# Feste Mess-/Flanken-Zeitstempel (Unix-ts) -- die lesbare Form wird je Test ueber
# datetime.fromtimestamp berechnet (zeitzonen-robust, s.o.).
_RTT_TS_A = 1_749_640_200.0
_RTT_TS_B = 1_749_640_260.0
_EVENT_TS = 1_749_640_230.0


def _iso(ts: float) -> str:
    """Spiegelt domain._ts_to_iso (lokale fromtimestamp) fuer die Erwartungswerte."""
    return datetime.fromtimestamp(ts).isoformat()


def _rtt(
    ts: float = _RTT_TS_A, rtt_ms: float = 12.5, loss_pct: float = 0.0, alive: bool = True
) -> ExportableLoggingRtt:
    return ExportableLoggingRtt(ts=ts, rtt_ms=rtt_ms, loss_pct=loss_pct, alive=alive)


def _event(
    ts: float = _EVENT_TS, event_type: str = "down", rtt_ms: float = -1.0
) -> ExportableLoggingEvent:
    return ExportableLoggingEvent(ts=ts, event_type=event_type, rtt_ms=rtt_ms)


def _report(
    *,
    rtt_points: tuple[ExportableLoggingRtt, ...] = (),
    events: tuple[ExportableLoggingEvent, ...] = (),
    uptime_pct: float | None = 99.5,
    avg_rtt_ms: float = 12.5,
    downtime_mins: float = 1.5,
    sample_count: int = 2,
    period_from: str = "2026-06-11T14:00:00",
    period_to: str = "2026-06-11T15:00:00",
) -> ExportableLoggingReport:
    return ExportableLoggingReport(
        task_label="WLAN-Gast",
        task_purpose="Stabilitaet pruefen",
        target_id="abc123",
        generated_at="2026-06-11T15:30:00+00:00",
        period_from=period_from,
        period_to=period_to,
        uptime_pct=uptime_pct,
        avg_rtt_ms=avg_rtt_ms,
        downtime_mins=downtime_mins,
        sample_count=sample_count,
        rtt_points=rtt_points,
        events=events,
    )


# ── logging_report_to_json (verlustfrei, sortierte Keys, roher ts + ts_iso) ────


def test_logging_report_to_json_is_lossless() -> None:
    report = _report(
        rtt_points=(_rtt(), _rtt(ts=_RTT_TS_B, rtt_ms=-1.0, loss_pct=100.0, alive=False)),
        events=(_event(),),
    )
    payload = json.loads(logging_report_to_json(report))

    assert payload["task_label"] == "WLAN-Gast"
    assert payload["task_purpose"] == "Stabilitaet pruefen"
    assert payload["target_id"] == "abc123"
    assert payload["generated_at"] == "2026-06-11T15:30:00+00:00"
    assert payload["period_from"] == "2026-06-11T14:00:00"
    assert payload["period_to"] == "2026-06-11T15:00:00"
    assert payload["uptime_pct"] == 99.5
    assert payload["avg_rtt_ms"] == 12.5
    assert payload["downtime_mins"] == 1.5
    assert payload["sample_count"] == 2

    # ALLE rtt_points verlustfrei, mit rohem ts UND lesbarem ts_iso.
    assert len(payload["rtt_points"]) == 2
    p0 = payload["rtt_points"][0]
    assert p0 == {
        "ts": _RTT_TS_A,
        "ts_iso": _iso(_RTT_TS_A),
        "rtt_ms": 12.5,
        "loss_pct": 0.0,
        "alive": True,
    }
    assert payload["rtt_points"][1]["alive"] is False
    assert payload["rtt_points"][1]["rtt_ms"] == -1.0

    # ALLE events verlustfrei.
    assert payload["events"] == [
        {"ts": _EVENT_TS, "ts_iso": _iso(_EVENT_TS), "event_type": "down", "rtt_ms": -1.0}
    ]


def test_logging_report_to_json_keys_are_sorted() -> None:
    payload = json.loads(logging_report_to_json(_report(rtt_points=(_rtt(),), events=(_event(),))))
    assert list(payload.keys()) == sorted(payload.keys())
    assert list(payload["rtt_points"][0].keys()) == sorted(payload["rtt_points"][0].keys())
    assert list(payload["events"][0].keys()) == sorted(payload["events"][0].keys())


def test_logging_report_to_json_is_deterministic() -> None:
    report = _report(rtt_points=(_rtt(), _rtt(ts=_RTT_TS_B)), events=(_event(),))
    assert logging_report_to_json(report) == logging_report_to_json(report)


def test_logging_report_to_json_uptime_none() -> None:
    payload = json.loads(logging_report_to_json(_report(uptime_pct=None, sample_count=0)))
    assert payload["uptime_pct"] is None


def test_logging_report_to_json_keeps_point_order() -> None:
    report = _report(rtt_points=(_rtt(ts=_RTT_TS_B), _rtt(ts=_RTT_TS_A)))
    payload = json.loads(logging_report_to_json(report))
    assert [p["ts"] for p in payload["rtt_points"]] == [_RTT_TS_B, _RTT_TS_A]


# ── logging_report_to_csv (NUR RTT-Reihe, Spalten, alive true/false) ───────────

_EXPECTED_LOGGING_CSV_HEADER = ["ts_iso", "rtt_ms", "loss_pct", "alive"]


def test_logging_report_to_csv_header_is_defined_order() -> None:
    rows = _parse_csv(logging_report_to_csv(_report(rtt_points=(_rtt(),))))
    assert rows[0] == _EXPECTED_LOGGING_CSV_HEADER


def test_logging_report_to_csv_row_values_in_column_order() -> None:
    rows = _parse_csv(logging_report_to_csv(_report(rtt_points=(_rtt(),))))
    assert rows[1] == [_iso(_RTT_TS_A), "12.5", "0.0", "true"]


def test_logging_report_to_csv_alive_false_is_false() -> None:
    rows = _parse_csv(
        logging_report_to_csv(_report(rtt_points=(_rtt(rtt_ms=-1.0, loss_pct=100.0, alive=False),)))
    )
    assert rows[1][_EXPECTED_LOGGING_CSV_HEADER.index("alive")] == "false"


def test_logging_report_to_csv_column_order_is_contract() -> None:
    """MUTATIONSPROBE: vertauschte Erwartungs-Spalten muessen rot sein."""
    rows = _parse_csv(logging_report_to_csv(_report(rtt_points=(_rtt(),))))
    swapped = ["rtt_ms", "ts_iso", *_EXPECTED_LOGGING_CSV_HEADER[2:]]
    assert rows[0] != swapped


def test_logging_report_to_csv_excludes_events() -> None:
    """Die CSV traegt NUR die RTT-Reihe -- die Events stehen NICHT drin (JSON/PDF haben sie)."""
    text = logging_report_to_csv(_report(rtt_points=(_rtt(),), events=(_event(event_type="down"),)))
    rows = _parse_csv(text)
    # Genau Header + eine RTT-Zeile -- keine zweite (Event-)Tabelle.
    assert len(rows) == 2
    assert "down" not in text


def test_logging_report_to_csv_empty_has_only_header() -> None:
    rows = _parse_csv(logging_report_to_csv(_report()))
    assert rows == [_EXPECTED_LOGGING_CSV_HEADER]


# ── build_logging_report_pdf_model (SLA-Kopf, Ereignis-Tabelle, Formate) ───────

_EXPECTED_LOGGING_PDF_COLUMNS = ("Zeitpunkt", "Ereignis", "RTT")


def test_build_logging_report_pdf_model_header_fields() -> None:
    model = build_logging_report_pdf_model(_report(events=(_event(),)))
    assert model.title == "CERNIS PRO — Monitoring-Bericht"
    assert model.meta == (
        ("Aufgabe", "WLAN-Gast"),
        ("Zweck", "Stabilitaet pruefen"),
        ("Ziel", "abc123"),
        ("Zeitraum", "2026-06-11T14:00:00 — 2026-06-11T15:00:00"),
        ("Verfügbarkeit", "99.5 %"),
        ("Ø-RTT", "12.5 ms"),
        ("ca. Ausfallzeit", "1.5 Min"),
        ("Messpunkte", "2"),
    )


def test_build_logging_report_pdf_model_uptime_none() -> None:
    """uptime_pct None -> "keine Auswertung" (kein erfundener 0%-Wert)."""
    model = build_logging_report_pdf_model(_report(uptime_pct=None, sample_count=0))
    verfuegbarkeit = dict(model.meta)["Verfügbarkeit"]
    assert verfuegbarkeit == "keine Auswertung"


def test_build_logging_report_pdf_model_period_open() -> None:
    """Offener Zeitraum (beide Grenzen "") -> "gesamter Zeitraum"."""
    model = build_logging_report_pdf_model(_report(period_from="", period_to=""))
    assert dict(model.meta)["Zeitraum"] == "gesamter Zeitraum"


def test_build_logging_report_pdf_model_period_half_open() -> None:
    """Nur eine Grenze gesetzt -> sprechende Halb-offen-Form."""
    only_from = build_logging_report_pdf_model(_report(period_to=""))
    assert dict(only_from.meta)["Zeitraum"] == "ab 2026-06-11T14:00:00"
    only_to = build_logging_report_pdf_model(_report(period_from=""))
    assert dict(only_to.meta)["Zeitraum"] == "bis 2026-06-11T15:00:00"


def test_build_logging_report_pdf_model_columns_are_event_list() -> None:
    model = build_logging_report_pdf_model(_report())
    assert model.columns == _EXPECTED_LOGGING_PDF_COLUMNS


def test_build_logging_report_pdf_model_event_rows() -> None:
    model = build_logging_report_pdf_model(_report(events=(_event(rtt_ms=42.0, event_type="up"),)))
    assert model.rows == ((_iso(_EVENT_TS), "up", "42.0"),)


def test_build_logging_report_pdf_model_excludes_rtt_points() -> None:
    """Die PDF-Tabelle ist die Ereignis-Liste -- die dichten RTT-Punkte sind NICHT drin."""
    model = build_logging_report_pdf_model(
        _report(rtt_points=(_rtt(), _rtt(ts=_RTT_TS_B)), events=(_event(),))
    )
    # Genau eine Zeile (das eine Event), NICHT die zwei RTT-Punkte.
    assert len(model.rows) == 1


def test_build_logging_report_pdf_model_columns_are_contract() -> None:
    """MUTATIONSPROBE: eine entfernte Spalte muss rot sein."""
    model = build_logging_report_pdf_model(_report())
    without_rtt = _EXPECTED_LOGGING_PDF_COLUMNS[:-1]
    assert model.columns != without_rtt


def test_build_logging_report_pdf_model_empty() -> None:
    model = build_logging_report_pdf_model(_report(events=(), sample_count=0, uptime_pct=None))
    assert model.rows == ()
    assert model.columns == _EXPECTED_LOGGING_PDF_COLUMNS
