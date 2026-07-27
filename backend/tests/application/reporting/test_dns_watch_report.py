"""Tests fuer die reine Aggregation ``build_dns_watch_report`` (DNS-Waechter, Etappe 1).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-Importe.
Die Funktion bekommt schon NEUTRALE, fertig projizierte Zeilen herein (der Composition
Root projiziert ``DnsContact`` samt Kategorie-Einordnung/Anzeige-Texten darauf) und
zaehlt/gruppiert/sortiert nur.

Abgedeckt: Leerfall (alle Zaehler 0, Kategorie-Verteilung genau drei Eintraege in
Reihenfolge, Durchreichen); gemischte Kategorien mit ``flagged_active`` = open + doh
(erwartungsgemaess NICHT geflaggt); quittierte Zeilen (aus aktiven Zaehlern/Verteilungen
ausgenommen, aber in ``contact_rows`` enthalten); Programm-Verteilung samt Platzhalter und
Sortierung; Sortierung der ``contact_rows`` (offen vor moegliche_doh vor erwartungsgemaess,
dann connection_count desc, dann remote_ip asc); Durchreichen von host_scope und beiden
Listen.
"""

from __future__ import annotations

from application.reporting import (
    CATEGORY_EXPECTED,
    CATEGORY_OPEN,
    CATEGORY_POSSIBLE_DOH,
    EMPTY_APP_MARKER,
    DnsWatchContactRow,
    DnsWatchReportInput,
    build_dns_watch_report,
)


def _row(
    remote_ip: str,
    *,
    category: str = CATEGORY_EXPECTED,
    app_name: str = "",
    connection_count: int = 1,
    acknowledged: bool = False,
) -> DnsWatchContactRow:
    """Baut eine neutrale DNS-Waechter-Zeile; nur die fuer den jeweiligen Test relevanten Felder.

    Die uebrigen Anzeige-/Sortier-Felder traegt der Composition Root sonst fertig; hier
    sind sie fuer die reine Rechnung ohne Belang und werden mit neutralen Werten gefuellt.
    """
    return DnsWatchContactRow(
        remote_ip=remote_ip,
        hostname="",
        category=category,
        app_name=app_name,
        port=0,
        connection_count=connection_count,
        acknowledged=acknowledged,
    )


def test_leere_rows_ergibt_nullzaehler_und_durchgereichten_rahmen() -> None:
    """T1: leere Eingabe -> alle Zaehler 0, Kategorie-Verteilung genau drei (Reihenfolge)."""
    status = DnsWatchReportInput(
        host_scope="local_host",
        expected_servers=("192.168.0.1",),
        doh_providers=("cloudflare-dns.com",),
    )

    report = build_dns_watch_report(status, [])

    assert report.contacts_total == 0
    assert report.active_total == 0
    assert report.acknowledged_total == 0
    assert report.expected_active == 0
    assert report.open_active == 0
    assert report.doh_active == 0
    assert report.flagged_active == 0
    # category_distribution: GENAU drei Eintraege, feste Reihenfolge, alle count 0.
    assert [(c.category, c.count) for c in report.category_distribution] == [
        (CATEGORY_OPEN, 0),
        (CATEGORY_POSSIBLE_DOH, 0),
        (CATEGORY_EXPECTED, 0),
    ]
    assert report.app_distribution == []
    assert report.contact_rows == []
    # Rahmen durchgereicht.
    assert report.host_scope == "local_host"
    assert report.expected_servers == ("192.168.0.1",)
    assert report.doh_providers == ("cloudflare-dns.com",)


def test_gemischte_kategorien_flagged_ist_open_plus_doh() -> None:
    """T2: aktive Kategorien korrekt; flagged = open + doh; erwartungsgemaess NICHT geflaggt."""
    status = DnsWatchReportInput(host_scope="local_host", expected_servers=(), doh_providers=())
    rows = [
        _row("1.0.0.1", category=CATEGORY_OPEN),
        _row("1.0.0.2", category=CATEGORY_OPEN),
        _row("1.0.0.3", category=CATEGORY_POSSIBLE_DOH),
        _row("1.0.0.4", category=CATEGORY_EXPECTED),
        _row("1.0.0.5", category=CATEGORY_EXPECTED),
        _row("1.0.0.6", category=CATEGORY_EXPECTED),
    ]

    report = build_dns_watch_report(status, rows)

    assert report.open_active == 2
    assert report.doh_active == 1
    assert report.expected_active == 3
    # flagged = open + doh (2 + 1), erwartungsgemaess NICHT enthalten.
    assert report.flagged_active == 3
    assert [(c.category, c.count) for c in report.category_distribution] == [
        (CATEGORY_OPEN, 2),
        (CATEGORY_POSSIBLE_DOH, 1),
        (CATEGORY_EXPECTED, 3),
    ]


def test_quittierte_zeilen_ausgenommen_aber_in_contact_rows() -> None:
    """T3: quittierte zaehlen in acknowledged_total, NICHT in aktiven Zaehlern/Verteilungen."""
    status = DnsWatchReportInput(host_scope="local_host", expected_servers=(), doh_providers=())
    rows = [
        _row("1.0.0.1", category=CATEGORY_OPEN, app_name="firefox"),
        _row("1.0.0.2", category=CATEGORY_OPEN, app_name="firefox", acknowledged=True),
        _row("1.0.0.3", category=CATEGORY_POSSIBLE_DOH, app_name="chrome", acknowledged=True),
    ]

    report = build_dns_watch_report(status, rows)

    assert report.contacts_total == 3
    assert report.active_total == 1
    assert report.acknowledged_total == 2
    # aktive Zaehler nur ueber die eine nicht-quittierte (offen) Zeile.
    assert report.open_active == 1
    assert report.doh_active == 0
    assert report.flagged_active == 1
    # Distributionen nur ueber aktive Zeilen: genau ein Programm "firefox".
    assert [(a.app_name, a.count) for a in report.app_distribution] == [("firefox", 1)]
    # ALLE Zeilen (aktiv + quittiert) erscheinen in contact_rows.
    assert {r.remote_ip for r in report.contact_rows} == {"1.0.0.1", "1.0.0.2", "1.0.0.3"}
    assert len(report.contact_rows) == 3


def test_app_distribution_gruppierung_platzhalter_sortierung() -> None:
    """T4: Gruppierung je app_name, leerer app_name als Marker, Sortierung (-count, app_name)."""
    status = DnsWatchReportInput(host_scope="local_host", expected_servers=(), doh_providers=())
    rows = [
        _row("1.0.0.1", app_name="firefox"),
        _row("1.0.0.2", app_name="firefox"),
        _row("1.0.0.3", app_name="chrome"),
        _row("1.0.0.4", app_name="chrome"),
        _row("1.0.0.5", app_name=""),
    ]

    report = build_dns_watch_report(status, rows)

    # firefox=2, chrome=2, Leer-Marker=1 -> count desc, bei Gleichstand app_name asc.
    assert [(a.app_name, a.count) for a in report.app_distribution] == [
        ("chrome", 2),
        ("firefox", 2),
        (EMPTY_APP_MARKER, 1),
    ]


def test_contact_rows_sortierung_kategorie_dann_count_dann_ip() -> None:
    """T5: offen vor moegliche_doh vor erwartungsgemaess; innerhalb count desc, dann ip asc."""
    status = DnsWatchReportInput(host_scope="local_host", expected_servers=(), doh_providers=())
    expected_hoch = _row("9.9.9.9", category=CATEGORY_EXPECTED, connection_count=100)
    doh = _row("3.3.3.3", category=CATEGORY_POSSIBLE_DOH, connection_count=5)
    open_a = _row("2.2.2.2", category=CATEGORY_OPEN, connection_count=10)
    open_b = _row("1.1.1.1", category=CATEGORY_OPEN, connection_count=10)
    open_hoch = _row("8.8.8.8", category=CATEGORY_OPEN, connection_count=50)
    rows = [expected_hoch, doh, open_a, open_b, open_hoch]

    report = build_dns_watch_report(status, rows)

    # offen zuerst (Rang 0, untereinander count desc dann ip asc), dann moegliche_doh
    # (Rang 1), dann erwartungsgemaess (Rang 2 -- trotz hohem count zuletzt).
    assert [r.remote_ip for r in report.contact_rows] == [
        "8.8.8.8",  # offen, count 50
        "1.1.1.1",  # offen, count 10, ip asc vor 2.2.2.2
        "2.2.2.2",  # offen, count 10
        "3.3.3.3",  # moegliche_doh, count 5
        "9.9.9.9",  # erwartungsgemaess, count 100 -- Kategorie-Rang schlaegt count
    ]


def test_rahmen_wird_unveraendert_durchgereicht() -> None:
    """T6: host_scope, expected_servers, doh_providers unveraendert im Report."""
    status = DnsWatchReportInput(
        host_scope="local_host",
        expected_servers=("192.168.0.1", "fritz.box"),
        doh_providers=("cloudflare-dns.com", "dns.google"),
    )

    report = build_dns_watch_report(status, [_row("1.0.0.1", category=CATEGORY_OPEN)])

    assert report.host_scope == "local_host"
    assert report.expected_servers == ("192.168.0.1", "fritz.box")
    assert report.doh_providers == ("cloudflare-dns.com", "dns.google")
