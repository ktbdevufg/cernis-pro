"""Tests fuer die reine Aggregation ``build_outbound_report`` (Aussenkontakte, Etappe 1).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-Importe.
Die Funktion bekommt schon NEUTRALE, fertig projizierte Zeilen herein (der Composition
Root projiziert ``AggregatedContact`` samt Blocklist-Bewertung/``is_local``/Anzeige-Texten
darauf) und zaehlt/gruppiert/sortiert nur.

Abgedeckt: Leerfall; ``is_local``-Ausschluss aus Remote-/Verteilungs-/Flag-Zaehlern bei
Einschluss in ``contacts_total``/``connection_total``; Tracker-/Threat-/Flag-Zaehler
(BEIDE-Flags zaehlen nur 1x); Land-/Betreiber-Verteilung samt Platzhalter und Sortierung;
Sortierung der ``contact_rows`` (Threat vor Tracker vor neutral, dann total_count desc,
dann remote_ip asc); distinct ``countries_total``/``operators_total`` ueber nicht-lokale,
nicht-leere Werte.
"""

from __future__ import annotations

from application.reporting import (
    EMPTY_COUNTRY_MARKER,
    EMPTY_OPERATOR_MARKER,
    OutboundContactRow,
    OutboundReportInput,
    build_outbound_report,
)


def _row(
    remote_ip: str,
    *,
    country: str = "",
    operator: str = "",
    total_count: int = 1,
    is_local: bool = False,
    tracker_lists: tuple[str, ...] = (),
    threat_lists: tuple[str, ...] = (),
) -> OutboundContactRow:
    """Baut eine neutrale Kontakt-Zeile; nur die fuer den jeweiligen Test relevanten Felder.

    Die uebrigen Anzeige-/Sortier-Felder traegt der Composition Root sonst fertig; hier
    sind sie fuer die reine Rechnung ohne Belang und werden mit neutralen Werten gefuellt.
    """
    return OutboundContactRow(
        remote_ip=remote_ip,
        hostname="",
        country=country,
        operator=operator,
        asn="",
        app_name="",
        first_seen_text="",
        last_seen_text="",
        first_seen_ts=0.0,
        last_seen_ts=0.0,
        total_count=total_count,
        peak_count=0,
        is_local=is_local,
        tracker_lists=tracker_lists,
        threat_lists=threat_lists,
    )


def test_leere_rows_ergibt_nullzaehler_und_durchgereichten_bezug() -> None:
    """Leere Eingabe -> alle Zaehler 0, leere Verteilungen/Listen, Bezug durchgereicht."""
    status = OutboundReportInput(recording_label="Alle Aufzeichnungen", recording_scope="all")

    report = build_outbound_report(status, [])

    assert report.recording_label == "Alle Aufzeichnungen"
    assert report.recording_scope == "all"
    assert report.contacts_total == 0
    assert report.remote_total == 0
    assert report.local_total == 0
    assert report.connection_total == 0
    assert report.countries_total == 0
    assert report.operators_total == 0
    assert report.tracker_contacts == 0
    assert report.threat_contacts == 0
    assert report.flagged_contacts == 0
    assert report.country_distribution == []
    assert report.operator_distribution == []
    assert report.contact_rows == []


def test_lokale_zeilen_aus_remote_und_flags_ausgenommen_aber_in_gesamt_enthalten() -> None:
    """``is_local`` zaehlt in contacts_total/connection_total, nicht in remote/Flags."""
    status = OutboundReportInput(recording_label="X", recording_scope="single")
    rows = [
        _row("10.0.0.1", country="DE", operator="LAN", total_count=5, is_local=True),
        _row("1.1.1.1", country="US", operator="Cloudflare", total_count=3),
    ]

    report = build_outbound_report(status, rows)

    assert report.contacts_total == 2
    assert report.remote_total == 1
    assert report.local_total == 1
    # connection_total enthaelt die lokale Zeile (5) + die remote (3).
    assert report.connection_total == 8
    # Verteilungen/distinct-Zaehler nur ueber die nicht-lokale Zeile.
    assert report.countries_total == 1
    assert report.operators_total == 1
    assert [c.country for c in report.country_distribution] == ["US"]
    assert [o.operator for o in report.operator_distribution] == ["Cloudflare"]


def test_tracker_threat_und_flagged_zaehler_distinct() -> None:
    """tracker/threat einzeln; eine Zeile mit BEIDEN Flags zaehlt in flagged nur 1x."""
    status = OutboundReportInput(recording_label="X", recording_scope="single")
    rows = [
        _row("1.0.0.1", tracker_lists=("StevenBlack",)),
        _row("1.0.0.2", threat_lists=("Feodo",)),
        _row("1.0.0.3", tracker_lists=("EasyList",), threat_lists=("Feodo",)),
        _row("1.0.0.4"),
        # Lokale Zeile mit Flags wuerde nie vom Aufrufer kommen; zur Sicherheit ignoriert:
        _row("10.0.0.9", is_local=True, tracker_lists=("LAN",)),
    ]

    report = build_outbound_report(status, rows)

    # tracker: Zeilen 1 und 3 -> 2; threat: Zeilen 2 und 3 -> 2.
    assert report.tracker_contacts == 2
    assert report.threat_contacts == 2
    # flagged: Zeilen 1, 2, 3 (distinct) -> 3, NICHT 4 (Zeile 3 trotz zweier Flags nur 1x).
    assert report.flagged_contacts == 3


def test_country_und_operator_verteilung_gruppierung_platzhalter_sortierung() -> None:
    """Gruppierung, leere Werte als Marker, Sortierung count desc dann label asc."""
    status = OutboundReportInput(recording_label="X", recording_scope="single")
    rows = [
        _row("1.0.0.1", country="DE", operator="DTAG"),
        _row("1.0.0.2", country="DE", operator="DTAG"),
        _row("1.0.0.3", country="US", operator=""),
        _row("1.0.0.4", country="", operator="Hetzner"),
        _row("1.0.0.5", country="US", operator="Hetzner"),
    ]

    report = build_outbound_report(status, rows)

    # Land: DE=2, US=2, Leer-Marker=1 -> count desc, dann label asc (DE vor US).
    assert [(c.country, c.count) for c in report.country_distribution] == [
        ("DE", 2),
        ("US", 2),
        (EMPTY_COUNTRY_MARKER, 1),
    ]
    # Betreiber: DTAG=2, Hetzner=2, Leer-Marker=1 -> count desc, dann label asc.
    assert [(o.operator, o.count) for o in report.operator_distribution] == [
        ("DTAG", 2),
        ("Hetzner", 2),
        (EMPTY_OPERATOR_MARKER, 1),
    ]


def test_contact_rows_sortierung_threat_vor_tracker_vor_neutral() -> None:
    """Threat-Zeile vor Tracker-Zeile vor neutraler Zeile; innerhalb total_count desc, ip asc."""
    status = OutboundReportInput(recording_label="X", recording_scope="single")
    neutral_hoch = _row("9.9.9.9", total_count=100)
    neutral_a = _row("2.2.2.2", total_count=10)
    neutral_b = _row("3.3.3.3", total_count=10)
    tracker = _row("4.4.4.4", total_count=1, tracker_lists=("EasyList",))
    threat = _row("5.5.5.5", total_count=1, threat_lists=("Feodo",))
    lokal = _row("10.0.0.1", total_count=999, is_local=True)
    rows = [neutral_hoch, neutral_a, neutral_b, tracker, threat, lokal]

    report = build_outbound_report(status, rows)

    # Reihenfolge: Threat zuerst (Flag-Rang 0), dann Tracker (Rang 1), dann ALLES mit
    # Flag-Rang 2 nach total_count desc, bei Gleichstand remote_ip asc. Lokale tragen NIE
    # Flags und liegen damit immer in Rang 2 -- ihr hoher total_count zieht sie aber NACH
    # OBEN (Auftrag: "ausser sie haben hohen total_count, was egal ist"). 10.0.0.1 (999)
    # steht daher vor der neutralen 9.9.9.9 (100).
    assert [r.remote_ip for r in report.contact_rows] == [
        "5.5.5.5",  # Threat (Rang 0)
        "4.4.4.4",  # Tracker (Rang 1)
        "10.0.0.1",  # lokal, Rang 2, total 999 -- hoechster total_count zieht nach oben
        "9.9.9.9",  # neutral, total 100
        "2.2.2.2",  # neutral, total 10, ip asc vor 3.3.3.3
        "3.3.3.3",  # neutral, total 10
    ]


def test_countries_und_operators_total_distinct_ueber_nicht_lokale_nicht_leere() -> None:
    """distinct Land/Betreiber nur ueber nicht-lokale, nicht-leere Werte."""
    status = OutboundReportInput(recording_label="X", recording_scope="single")
    rows = [
        _row("1.0.0.1", country="DE", operator="DTAG"),
        _row("1.0.0.2", country="DE", operator="Hetzner"),  # DE doppelt -> 1 distinct Land
        _row("1.0.0.3", country="", operator=""),  # leere -> zaehlen NICHT
        _row("10.0.0.1", country="DE", operator="LAN", is_local=True),  # lokal -> ausgenommen
        _row("10.0.0.2", country="CH", operator="Swisscom", is_local=True),  # lokal -> ausgenommen
    ]

    report = build_outbound_report(status, rows)

    # Laender ueber nicht-lokal, nicht-leer: nur "DE" -> 1.
    assert report.countries_total == 1
    # Betreiber ueber nicht-lokal, nicht-leer: "DTAG", "Hetzner" -> 2.
    assert report.operators_total == 2
