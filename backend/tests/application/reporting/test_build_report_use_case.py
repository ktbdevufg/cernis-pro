"""Tests fuer den duennen Use-Case ``BuildSecurityReport`` (Sicherheitsbericht, 2b).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-
Importe. Der Use-Case nimmt die schon NEUTRALEN Eingabe-Datentraeger (der Composition
Root projiziert die echten Quell-Objekte darauf) und reicht sie UNVERAENDERT an
``build_security_report`` durch.

Abgedeckt: identisches Ergebnis zum direkten ``build_security_report``-Aufruf (Defaults);
Durchreichen eigener Gewichte/Schwellen; leere Eingabe -> Score 100 ueber leere Basis;
die quittierten Listen werden unveraendert durchgereicht (kein Eigenverhalten).
"""

from __future__ import annotations

from application.reporting import (
    BuildSecurityReport,
    CveFinding,
    NetFinding,
    PortFinding,
    build_security_report,
)


def test_reicht_mit_defaults_identisch_zu_build_security_report_durch() -> None:
    """Der Use-Case liefert mit Defaults GENAU dasselbe wie der direkte Funktionsaufruf."""
    device_labels = ["dev-crit", "dev-cve", "dev-sauber"]
    port_findings = [
        PortFinding(device_label="dev-crit", ports="23", severity="critical", reason="Telnet"),
    ]
    cve_findings = [
        CveFinding(
            device_label="dev-cve",
            cve_id="CVE-2021-0001",
            cvss_score=7.5,
            severity="high",
            service="http",
            description="CVE-2021-0001",
        ),
    ]
    net_findings = [
        NetFinding(
            kind="DNS-Umgehung",
            device_label="8.8.8.8",
            description="offen",
            severity="notable",
        ),
    ]
    ack_port = [
        PortFinding(device_label="dev-cve", ports="22", severity="notable", reason="SSH"),
    ]

    report = BuildSecurityReport()(
        device_labels=device_labels,
        port_findings=port_findings,
        cve_findings=cve_findings,
        net_findings=net_findings,
        ack_port=ack_port,
        ack_cve=[],
        ack_net=[],
    )
    expected = build_security_report(
        device_labels=device_labels,
        port_findings=port_findings,
        cve_findings=cve_findings,
        net_findings=net_findings,
        ack_port=ack_port,
        ack_cve=[],
        ack_net=[],
    )

    assert report == expected
    # Spot-Checks: die quittierte Liste wird unveraendert durchgereicht (kein Eigenverhalten).
    assert report.acknowledged_port_findings == ack_port
    assert report.device_labels == device_labels


def test_reicht_eigene_gewichte_und_schwellen_durch() -> None:
    """Hereingereichte Gewichte/Schwellen wirken -- der Use-Case faelscht keine Defaults.

    Mit ``cvss_critical_min=7.0`` wird der CVE (cvss 7.5) zu "critical" statt "notable" --
    das Ergebnis muss dem direkten Funktionsaufruf mit derselben Schwelle gleichen.
    """
    device_labels = ["dev-cve"]
    cve_findings = [
        CveFinding(
            device_label="dev-cve",
            cve_id="CVE-2021-0002",
            cvss_score=7.5,
            severity="high",
            service="http",
            description="CVE-2021-0002",
        ),
    ]

    report = BuildSecurityReport()(
        device_labels=device_labels,
        port_findings=[],
        cve_findings=cve_findings,
        net_findings=[],
        ack_port=[],
        ack_cve=[],
        ack_net=[],
        cvss_critical_min=7.0,
    )
    expected = build_security_report(
        device_labels=device_labels,
        port_findings=[],
        cve_findings=cve_findings,
        net_findings=[],
        ack_port=[],
        ack_cve=[],
        ack_net=[],
        cvss_critical_min=7.0,
    )

    assert report == expected
    assert report.score.critical_devices == 1


def test_leere_eingabe_ergibt_score_100_ueber_leere_basis() -> None:
    """Ehrlicher Leerfall (kein Scan): leere Listen -> Score 100 ueber leere Basis."""
    report = BuildSecurityReport()(
        device_labels=[],
        port_findings=[],
        cve_findings=[],
        net_findings=[],
        ack_port=[],
        ack_cve=[],
        ack_net=[],
    )
    assert report.score.score == 100
    assert report.device_labels == []
    assert report.port_findings == []
    assert report.cve_findings == []
    assert report.net_findings == []
