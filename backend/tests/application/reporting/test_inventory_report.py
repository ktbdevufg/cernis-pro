"""Tests fuer die reine Aggregation ``build_inventory_report`` (Bestandsbericht).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-Importe.
Die Funktion bekommt schon NEUTRALE, fertig projizierte Zeilen herein (der Composition
Root projiziert die echten Device-Objekte darauf) und zaehlt/gruppiert/sortiert nur.

Schwerpunkt hier: die beiden Verteilungen und ihre LEER-Marker. Ein leerer Hersteller /
eine leere Kategorie wird als MASCHINELLER Marker gezaehlt, nicht als deutscher
Anzeigetext -- die Beschriftung entsteht erst beim Uebersetzen (Frontend/PDF). Die
Verteilungen haben dabei UNTERSCHIEDLICHE Marker, damit beide einen eigenen Wortlaut
bekommen koennen.
"""

from __future__ import annotations

from application.reporting import (
    EMPTY_CATEGORY_MARKER,
    EMPTY_VENDOR_MARKER,
    InventoryDeviceRow,
    InventoryReport,
    build_inventory_report,
)


def _row(
    device_label: str,
    *,
    vendor: str = "",
    category: str = "",
    last_seen_ts: float = 0.0,
    trust_state: str = "neutral",
    archived: bool = False,
) -> InventoryDeviceRow:
    """Baut eine neutrale Geraete-Zeile; nur die fuer den jeweiligen Test relevanten Felder.

    Die uebrigen Anzeige-Felder traegt der Composition Root sonst fertig; hier sind sie
    fuer die reine Rechnung ohne Belang und werden mit neutralen Werten gefuellt.
    """
    return InventoryDeviceRow(
        device_label=device_label,
        vendor=vendor,
        last_ip="",
        first_seen_text="",
        last_seen_text="",
        last_seen_ts=last_seen_ts,
        times_seen=1,
        category=category,
        is_known=True,
        trust_state=trust_state,
        source="scan",
        archived=archived,
    )


def _report(rows: list[InventoryDeviceRow]) -> InventoryReport:
    """Ruft die Aggregation mit neutralen Kennzahlen auf (nur die Zeilen zaehlen hier)."""
    return build_inventory_report(
        total=len(rows), known=len(rows), unknown=0, active_24h=0, rows=rows
    )


def test_leere_werte_werden_als_maschineller_marker_gezaehlt() -> None:
    """T1: Leerer Hersteller/leere Kategorie -> Marker, KEIN Anzeigetext.

    Der rohe Marker ist der Vertrag zwischen Aggregation und Anzeigeschicht; ein
    deutscher Text an dieser Stelle waere der Fehler, den dieser Test verhindert.
    """
    report = _report([_row("A"), _row("B")])

    assert [(e.label, e.count) for e in report.vendor_distribution] == [(EMPTY_VENDOR_MARKER, 2)]
    assert [(e.label, e.count) for e in report.category_distribution] == [
        (EMPTY_CATEGORY_MARKER, 2)
    ]


def test_die_beiden_verteilungen_nutzen_unterschiedliche_marker() -> None:
    """T2: Hersteller- und Kategorie-Marker sind verschieden.

    Nur so kann jede Verteilung ihren eigenen Wortlaut bekommen ("Kein Hersteller
    ermittelt" vs. "Keine Kategorie ermittelt"), obwohl beide denselben Sachverhalt
    beschreiben.
    """
    assert EMPTY_VENDOR_MARKER != EMPTY_CATEGORY_MARKER

    report = _report([_row("A")])
    vendor_labels = {e.label for e in report.vendor_distribution}
    category_labels = {e.label for e in report.category_distribution}

    assert vendor_labels == {EMPTY_VENDOR_MARKER}
    assert category_labels == {EMPTY_CATEGORY_MARKER}


def test_kein_anzeigetext_schlaegt_als_label_durch() -> None:
    """T3: Die alte Klammerform "(ohne)" entsteht nirgends mehr in den Verteilungen."""
    report = _report([_row("A", vendor="NETGEAR"), _row("B"), _row("C", category="TV")])

    alle_labels = [e.label for e in report.vendor_distribution] + [
        e.label for e in report.category_distribution
    ]
    assert "(ohne)" not in alle_labels
    assert "(none)" not in alle_labels


def test_gefuellte_werte_werden_unveraendert_durchgereicht() -> None:
    """T4: Nicht-leere Hersteller/Kategorien bleiben wortgleich, nur leere werden ersetzt."""
    report = _report(
        [
            _row("A", vendor="NETGEAR", category="Router"),
            _row("B", vendor="NETGEAR", category=""),
            _row("C", vendor="", category="Router"),
        ]
    )

    assert [(e.label, e.count) for e in report.vendor_distribution] == [
        ("NETGEAR", 2),
        (EMPTY_VENDOR_MARKER, 1),
    ]
    assert [(e.label, e.count) for e in report.category_distribution] == [
        ("Router", 2),
        (EMPTY_CATEGORY_MARKER, 1),
    ]


def test_sortierung_bleibt_count_desc_dann_label_asc() -> None:
    """T5: Sortierregel unveraendert -- absteigend nach count, bei Gleichstand label asc.

    Der Marker nimmt an der Sortierung teil wie jedes andere Label auch; die REGEL
    aendert sich durch ihn nicht.
    """
    report = _report(
        [
            _row("A", vendor="Zyxel"),
            _row("B", vendor="Acme"),
            _row("C", vendor="NETGEAR"),
            _row("D", vendor="NETGEAR"),
        ]
    )

    assert [(e.label, e.count) for e in report.vendor_distribution] == [
        ("NETGEAR", 2),
        ("Acme", 1),
        ("Zyxel", 1),
    ]


def test_archivierte_zeilen_zaehlen_in_beide_verteilungen_mit() -> None:
    """T6: Die Verteilungen gehen ueber ALLE Zeilen (auch archivierte) -- unveraendert."""
    report = _report([_row("A", vendor="Acme"), _row("B", vendor="Acme", archived=True)])

    assert [(e.label, e.count) for e in report.vendor_distribution] == [("Acme", 2)]
