"""Duenner Use-Case ``BuildSecurityReport`` (Sicherheitsbericht, Etappe 2b).

Der Use-Case sitzt zwischen dem Composition Root (app.py, der die fuenf echten
Quellen abruft und auf die NEUTRALEN Eingabe-Datentraeger projiziert) und der reinen
Aggregation ``build_security_report``. Er ist BEWUSST trivial: er nimmt die FERTIGEN
neutralen Listen (samt ``device_labels`` und den optionalen Gewichten/Schwellen)
entgegen und reicht sie unveraendert an ``build_security_report`` durch.

KEINE Eigenlogik ausser dem Durchreichen, KEINE Domaenen-Importe, KEINE Repos, KEINE
I/O, KEINE Uhr (CLAUDE.md, Importregel application -> domain/ports). Die Projektion
der echten Quell-Objekte (ActiveFinding/ArpAlertRecord/DnsContact/LatestRogueDhcp ...)
auf die neutralen Typen liegt -- weil sie alle Domaenen kennt -- AUSSCHLIESSLICH im
Composition Root; dieser Use-Case bleibt domaenen-blind und damit voll testbar.

Die Gewichte/Schwellen kommen mit denselben Defaults wie ``build_security_report``
herein (spaeter aus analysis-Settings) -- dieselbe Naht wie bei den reinen Funktionen.
"""

from __future__ import annotations

from application.reporting.inventory_report import (
    InventoryDeviceRow,
    InventoryReport,
    build_inventory_report,
)
from application.reporting.security_report import (
    CveFinding,
    NetFinding,
    PortFinding,
    SecurityReport,
    build_security_report,
)

__all__ = ["BuildInventoryReport", "BuildSecurityReport"]


class BuildSecurityReport:
    """Duenner Pass-Through: fertige neutrale Listen -> ``build_security_report``.

    Duenn (Muster ``ResolveDns``/``GetArpAlerts``): keine eigene Logik ausser dem
    Durchreichen. ``__call__`` nimmt die schon NEUTRALEN Befund-Listen (der Composition
    Root hat die echten Quell-Objekte darauf projiziert) plus ``device_labels`` (Basis N)
    und die optionalen Gewichte/Schwellen mit denselben Defaults wie
    ``build_security_report`` und gibt den ``SecurityReport`` zurueck.
    """

    def __call__(
        self,
        device_labels: list[str],
        port_findings: list[PortFinding],
        cve_findings: list[CveFinding],
        net_findings: list[NetFinding],
        ack_port: list[PortFinding],
        ack_cve: list[CveFinding],
        ack_net: list[NetFinding],
        critical_weight: float = 1.0,
        notable_weight: float = 0.3334,
        level_good_min: int = 80,
        level_mid_min: int = 50,
        cvss_critical_min: float = 9.0,
    ) -> SecurityReport:
        """Reicht die fertigen neutralen Listen + Gewichte/Schwellen unveraendert durch.

        Kein Eigenverhalten: ruft ``build_security_report`` mit GENAU den hereingereichten
        Werten und gibt dessen ``SecurityReport`` zurueck. Die Defaults sind zeichengleich
        zu ``build_security_report`` -- ein Aufrufer ohne Gewichte/Schwellen bekommt das
        identische Ergebnis wie ein direkter Funktionsaufruf.
        """
        return build_security_report(
            device_labels,
            port_findings,
            cve_findings,
            net_findings,
            ack_port,
            ack_cve,
            ack_net,
            critical_weight=critical_weight,
            notable_weight=notable_weight,
            level_good_min=level_good_min,
            level_mid_min=level_mid_min,
            cvss_critical_min=cvss_critical_min,
        )


class BuildInventoryReport:
    """Duenner Pass-Through: fertige neutrale Zeilen + Grundzahlen -> ``build_inventory_report``.

    Duenn (Muster ``BuildSecurityReport``/``ResolveDns``): keine eigene Logik ausser dem
    Durchreichen. ``__call__`` nimmt die schon NEUTRALEN Geraete-Zeilen (der Composition
    Root hat die echten Device-Objekte darauf projiziert) plus die Bestands-Grundzahlen
    (``total``/``known``/``unknown``/``active_24h`` aus ``DeviceStats``) und gibt den
    ``InventoryReport`` zurueck. KEINE Domaenen-Importe, KEINE Repos, KEINE I/O, KEINE Uhr.
    """

    def __call__(
        self,
        total: int,
        known: int,
        unknown: int,
        active_24h: int,
        rows: list[InventoryDeviceRow],
    ) -> InventoryReport:
        """Reicht die fertigen neutralen Zeilen + Grundzahlen unveraendert durch.

        Kein Eigenverhalten: ruft ``build_inventory_report`` mit GENAU den hereingereichten
        Werten und gibt dessen ``InventoryReport`` zurueck.
        """
        return build_inventory_report(
            total,
            known,
            unknown,
            active_24h,
            rows,
        )
