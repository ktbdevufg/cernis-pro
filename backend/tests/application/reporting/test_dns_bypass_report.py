"""Tests fuer die reine Aggregation ``build_dns_bypass_report`` (DNS-Umgehung, Etappe 5).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-Importe.
Die Funktion bekommt schon NEUTRALE, fertig projizierte Umgehungs-Zeilen herein (der
Composition Root projiziert die ``AggregatedBypass``-Aggregate samt device_name/DoH-
Bewertung darauf) plus den DETAIL-Gesamtstand ``queries_total`` und zaehlt/gruppiert/
sortiert nur.

Abgedeckt: Leerfall (Bezug/expected_servers durchgereicht); Kennzahlen (bypass_total als
Summe, expected_total = queries_total - bypass_total nie negativ, bypass_devices distinct);
Ziel-Resolver-Verteilung (Summe je dst_ip, count desc dann dst_ip asc); Sortierung der
bypass_rows (query_count desc, dann src_ip asc, dann dst_ip asc).
"""

from __future__ import annotations

from application.reporting import (
    DnsBypassReportInput,
    DnsBypassReportRow,
    build_dns_bypass_report,
)


def _row(
    src_ip: str,
    dst_ip: str,
    *,
    query_count: int = 1,
    device_name: str = "",
    is_doh: bool = False,
    doh_source_name: str = "",
    sample_qnames: tuple[str, ...] = (),
) -> DnsBypassReportRow:
    """Baut eine neutrale Umgehungs-Zeile; nur die fuer den jeweiligen Test relevanten Felder.

    Die uebrigen Anzeige-Felder traegt der Composition Root sonst fertig; hier sind sie fuer
    die reine Rechnung ohne Belang und werden mit neutralen Werten gefuellt.
    """
    return DnsBypassReportRow(
        src_ip=src_ip,
        device_name=device_name,
        dst_ip=dst_ip,
        is_doh=is_doh,
        doh_source_name=doh_source_name,
        query_count=query_count,
        sample_qnames=sample_qnames,
    )


def test_leere_rows_ergibt_nullzaehler_und_durchgereichten_bezug() -> None:
    """Leere Eingabe -> alle Zaehler 0, leere Verteilung/Liste, Bezug + Beleg durchgereicht."""
    status = DnsBypassReportInput(
        recording_label="Alle Aufzeichnungen",
        recording_scope="all",
        expected_servers=("192.168.1.1",),
    )

    report = build_dns_bypass_report(status, [], 0)

    assert report.recording_label == "Alle Aufzeichnungen"
    assert report.recording_scope == "all"
    assert report.expected_servers == ("192.168.1.1",)
    assert report.queries_total == 0
    assert report.bypass_total == 0
    assert report.expected_total == 0
    assert report.bypass_devices == 0
    assert report.resolver_distribution == []
    assert report.bypass_rows == []


def test_kennzahlen_bypass_expected_und_devices() -> None:
    """bypass_total = Summe; expected_total = queries_total - bypass_total; devices distinct."""
    status = DnsBypassReportInput(
        recording_label="X", recording_scope="single", expected_servers=()
    )
    rows = [
        _row("10.0.0.1", "8.8.8.8", query_count=5),
        _row("10.0.0.1", "1.1.1.1", query_count=3),  # dasselbe Geraet, anderes Ziel
        _row("10.0.0.2", "8.8.8.8", query_count=2),
    ]

    # queries_total (alle DETAIL-Zeilen des Laufs) = 20; Umgehungen = 5+3+2 = 10.
    report = build_dns_bypass_report(status, rows, 20)

    assert report.bypass_total == 10
    assert report.expected_total == 10  # 20 - 10
    # distinct src_ip: 10.0.0.1, 10.0.0.2 -> 2.
    assert report.bypass_devices == 2


def test_expected_total_nie_negativ() -> None:
    """Ist bypass_total > queries_total (Retention/Fenster-Randfall), bleibt expected_total 0."""
    status = DnsBypassReportInput(
        recording_label="X", recording_scope="single", expected_servers=()
    )
    rows = [_row("10.0.0.1", "8.8.8.8", query_count=9)]

    # queries_total kleiner als bypass_total -> max(.., 0) greift, nie negativ.
    report = build_dns_bypass_report(status, rows, 4)

    assert report.bypass_total == 9
    assert report.expected_total == 0


def test_resolver_verteilung_summe_je_dst_ip_und_sortierung() -> None:
    """Summe der query_count je dst_ip; Sortierung count desc, dann dst_ip asc."""
    status = DnsBypassReportInput(
        recording_label="X", recording_scope="single", expected_servers=()
    )
    rows = [
        _row("10.0.0.1", "8.8.8.8", query_count=3),
        _row("10.0.0.2", "8.8.8.8", query_count=2),  # 8.8.8.8 gesamt 5
        _row("10.0.0.3", "1.1.1.1", query_count=5),  # 1.1.1.1 gesamt 5
        _row("10.0.0.4", "9.9.9.9", query_count=1),  # 9.9.9.9 gesamt 1
    ]

    report = build_dns_bypass_report(status, rows, 100)

    # 8.8.8.8=5, 1.1.1.1=5, 9.9.9.9=1 -> count desc, bei Gleichstand dst_ip asc
    # (1.1.1.1 vor 8.8.8.8).
    assert [(r.dst_ip, r.count) for r in report.resolver_distribution] == [
        ("1.1.1.1", 5),
        ("8.8.8.8", 5),
        ("9.9.9.9", 1),
    ]


def test_bypass_rows_sortierung_query_count_dann_src_ip_dann_dst_ip() -> None:
    """query_count desc; bei Gleichstand src_ip asc; dann dst_ip asc (stabil)."""
    status = DnsBypassReportInput(
        recording_label="X", recording_scope="single", expected_servers=()
    )
    laut = _row("10.0.0.9", "8.8.8.8", query_count=100)
    gleich_a1 = _row("10.0.0.2", "1.1.1.1", query_count=10)
    gleich_a2 = _row("10.0.0.2", "9.9.9.9", query_count=10)  # gleiche src, dst asc danach
    gleich_b = _row("10.0.0.3", "1.1.1.1", query_count=10)
    rows = [gleich_b, gleich_a2, laut, gleich_a1]

    report = build_dns_bypass_report(status, rows, 200)

    assert [(r.src_ip, r.dst_ip) for r in report.bypass_rows] == [
        ("10.0.0.9", "8.8.8.8"),  # query_count 100 zuerst
        ("10.0.0.2", "1.1.1.1"),  # 10, src asc, dst 1.1.1.1
        ("10.0.0.2", "9.9.9.9"),  # 10, src 10.0.0.2, dst 9.9.9.9
        ("10.0.0.3", "1.1.1.1"),  # 10, src 10.0.0.3
    ]


def test_bezug_und_expected_servers_werden_unveraendert_durchgereicht() -> None:
    """recording_label/scope/expected_servers landen 1:1 im Report (roher Beleg)."""
    status = DnsBypassReportInput(
        recording_label="Büro-Lauf",
        recording_scope="single",
        expected_servers=("192.168.1.1", "192.168.1.2"),
    )

    report = build_dns_bypass_report(status, [_row("10.0.0.1", "8.8.8.8", query_count=1)], 1)

    assert report.recording_label == "Büro-Lauf"
    assert report.recording_scope == "single"
    assert report.expected_servers == ("192.168.1.1", "192.168.1.2")
