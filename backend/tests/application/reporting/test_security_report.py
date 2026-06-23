"""Tests fuer die reine Berichts-Aggregation (Sicherheitsbericht, Etappe 2).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-
Importe. Die Rohbefunde kommen als neutrale Eingabe-Datentraeger herein (der
Aufrufer/2b projiziert die echten Quell-Objekte darauf) -- so bleibt die
Aggregation voll deterministisch pruefbar.

Abgedeckt: schwerstes Vergehen je Geraet als Maximum ueber Quellen; CVE-Mapping an
der Default-Schwelle (9.0 -> critical, 8.9 -> notable); Geraet ohne Befund -> "none";
acknowledged-Befunde aendern die Burdens NICHT; Sortierung der drei offenen Listen;
End-to-End-Score-Integration (89); acknowledged-Listen unveraendert durchgereicht;
leere Eingabe -> leerer Report mit Score 100.
"""

from __future__ import annotations

from application.reporting.security_report import (
    CveFinding,
    NetFinding,
    PortFinding,
    build_device_burdens,
    build_security_report,
    severity_rank,
)


def test_severity_rank_ordnet_critical_ueber_notable_ueber_none() -> None:
    """critical > notable > none; Unbekanntes rangiert wie none."""
    assert severity_rank("critical") > severity_rank("notable")
    assert severity_rank("notable") > severity_rank("none")
    assert severity_rank("unbekannt") == severity_rank("none") == 0


def test_burden_maximum_ueber_quellen_port_critical_plus_cve_notable() -> None:
    """Ein Geraet mit Port-critical + CVE-notable -> worst "critical" (Maximum)."""
    burdens = build_device_burdens(
        device_labels=["dev-1"],
        port_findings=[
            PortFinding(device_label="dev-1", ports="23", severity="critical", reason="Telnet"),
        ],
        cve_findings=[
            CveFinding(
                device_label="dev-1",
                cve_id="CVE-2020-0001",
                cvss_score=5.0,  # < 9.0 -> notable
                severity="medium",
                service="http",
                description="Beispielhafte Schwachstelle",
            ),
        ],
        net_findings=[],
    )
    assert len(burdens) == 1
    assert burdens[0].device_label == "dev-1"
    assert burdens[0].worst_severity == "critical"


def test_cve_mapping_an_der_default_schwelle() -> None:
    """CVSS 9.0 -> critical, 8.9 -> notable (Default-Schwelle 9.0)."""
    burdens = build_device_burdens(
        device_labels=["grenz-hoch", "grenz-knapp"],
        port_findings=[],
        cve_findings=[
            CveFinding(
                device_label="grenz-hoch",
                cve_id="CVE-A",
                cvss_score=9.0,
                severity="critical",
                service="ssh",
                description="Schwachstelle A",
            ),
            CveFinding(
                device_label="grenz-knapp",
                cve_id="CVE-B",
                cvss_score=8.9,
                severity="high",
                service="ssh",
                description="Schwachstelle B",
            ),
        ],
        net_findings=[],
    )
    by_label = {b.device_label: b.worst_severity for b in burdens}
    assert by_label["grenz-hoch"] == "critical"
    assert by_label["grenz-knapp"] == "notable"


def test_geraet_ohne_befund_ist_none() -> None:
    """Ein Geraet ohne jeden offenen Befund -> worst_severity "none"."""
    burdens = build_device_burdens(
        device_labels=["sauber"],
        port_findings=[],
        cve_findings=[],
        net_findings=[],
    )
    assert burdens[0].worst_severity == "none"


def test_acknowledged_befunde_aendern_burdens_nicht() -> None:
    """Quittierte Befunde werden gar nicht als offen gereicht -> Geraet bleibt "none"."""
    # build_device_burdens kennt nur offene Befunde; die ack-Listen reicht erst
    # build_security_report durch. Hier: Geraet hat NUR quittierte Befunde -> die
    # tauchen in den offenen Listen nicht auf, also bleibt das Geraet "none".
    report = build_security_report(
        device_labels=["dev-quittiert"],
        port_findings=[],
        cve_findings=[],
        net_findings=[],
        ack_port=[
            PortFinding(
                device_label="dev-quittiert", ports="23", severity="critical", reason="Telnet"
            ),
        ],
        ack_cve=[],
        ack_net=[],
    )
    assert report.score.critical_devices == 0
    assert report.score.clean_devices == 1
    assert report.score.score == 100


def test_sortierung_der_drei_offenen_listen() -> None:
    """Ports: critical vor notable dann device_label; CVE: cvss desc; Netz: critical vor notable."""
    report = build_security_report(
        device_labels=["a", "b", "c", "d"],
        port_findings=[
            PortFinding(device_label="z-dev", ports="80", severity="notable", reason="HTTP"),
            PortFinding(device_label="m-dev", ports="23", severity="critical", reason="Telnet"),
            PortFinding(device_label="a-dev", ports="23", severity="critical", reason="Telnet"),
        ],
        cve_findings=[
            CveFinding(
                device_label="a",
                cve_id="C-low",
                cvss_score=4.0,
                severity="medium",
                service="x",
                description="C-low",
            ),
            CveFinding(
                device_label="b",
                cve_id="C-high",
                cvss_score=9.8,
                severity="critical",
                service="y",
                description="C-high",
            ),
            CveFinding(
                device_label="c",
                cve_id="C-mid",
                cvss_score=7.5,
                severity="high",
                service="z",
                description="C-mid",
            ),
        ],
        net_findings=[
            NetFinding(
                kind="DNS-Umgehung", device_label="d", description="DoH", severity="notable"
            ),
            NetFinding(
                kind="IP-Konflikt", device_label="a", description="Konflikt", severity="critical"
            ),
        ],
        ack_port=[],
        ack_cve=[],
        ack_net=[],
    )
    # Ports: beide critical (nach device_label a-dev, m-dev), dann notable z-dev.
    assert [p.device_label for p in report.port_findings] == ["a-dev", "m-dev", "z-dev"]
    # CVE: nach cvss_score absteigend.
    assert [c.cve_id for c in report.cve_findings] == ["C-high", "C-mid", "C-low"]
    # Netz: critical vor notable.
    assert [n.severity for n in report.net_findings] == ["critical", "notable"]


def test_score_integration_end_to_end_89() -> None:
    """2 Geraete critical + 2 notable unter 24 device_labels -> Score 89 (wie Etappe 1)."""
    # 24 Geraete: c0/c1 critical (je 1 Port-critical), n0/n1 notable (je 1 CVE < 9.0),
    # der Rest sauber. total_burden = 2*1.0 + 2*0.3334 = 2.6668;
    # score = round(100 * (1 - 2.6668/24)) = round(88.888...) = 89.
    device_labels = [f"dev-{i}" for i in range(24)]
    port_findings = [
        PortFinding(device_label="dev-0", ports="23", severity="critical", reason="Telnet"),
        PortFinding(device_label="dev-1", ports="2323", severity="critical", reason="Telnet"),
    ]
    cve_findings = [
        CveFinding(
            device_label="dev-2",
            cve_id="CVE-X",
            cvss_score=5.0,
            severity="medium",
            service="http",
            description="CVE-X",
        ),
        CveFinding(
            device_label="dev-3",
            cve_id="CVE-Y",
            cvss_score=6.0,
            severity="medium",
            service="http",
            description="CVE-Y",
        ),
    ]
    report = build_security_report(
        device_labels=device_labels,
        port_findings=port_findings,
        cve_findings=cve_findings,
        net_findings=[],
        ack_port=[],
        ack_cve=[],
        ack_net=[],
    )
    assert report.score.device_count == 24
    assert report.score.critical_devices == 2
    assert report.score.notable_devices == 2
    assert report.score.clean_devices == 20
    assert report.score.score == 89
    assert report.score.level == "gut"


def test_acknowledged_listen_unveraendert_durchgereicht() -> None:
    """Die ack_*-Listen werden identisch (gleiche Objekte/Reihenfolge) durchgereicht."""
    ack_port = [
        PortFinding(device_label="x", ports="22", severity="notable", reason="SSH"),
    ]
    ack_cve = [
        CveFinding(
            device_label="x",
            cve_id="CVE-Z",
            cvss_score=3.0,
            severity="low",
            service="ssh",
            description="CVE-Z",
        ),
    ]
    ack_net = [
        NetFinding(kind="Rogue-DHCP", device_label="x", description="DHCP", severity="critical"),
    ]
    report = build_security_report(
        device_labels=["x"],
        port_findings=[],
        cve_findings=[],
        net_findings=[],
        ack_port=ack_port,
        ack_cve=ack_cve,
        ack_net=ack_net,
    )
    assert report.acknowledged_port_findings == ack_port
    assert report.acknowledged_cve_findings == ack_cve
    assert report.acknowledged_net_findings == ack_net


def test_leere_eingabe_leerer_report_score_100() -> None:
    """device_labels leer -> leerer Report, Score 100 (ueber compute_security_score)."""
    report = build_security_report(
        device_labels=[],
        port_findings=[],
        cve_findings=[],
        net_findings=[],
        ack_port=[],
        ack_cve=[],
        ack_net=[],
    )
    assert report.device_labels == []
    assert report.port_findings == []
    assert report.cve_findings == []
    assert report.net_findings == []
    assert report.score.score == 100
    assert report.score.level == "gut"
    assert report.score.device_count == 0
