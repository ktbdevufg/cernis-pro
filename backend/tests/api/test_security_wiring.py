"""Verdrahtungs-Smoke der security-Domaene (SEC.6) gegen das echte ``create_app``.

AUFLAGE B (Wiederverwendung): RunArpScan, das app.py instanziiert, nutzt DIESELBEN
scanning-Adapter-Instanzen (ArpTablePort/VendorLookupPort) wie der scanning-Block --
KEIN zweiter ArpTable/Vendor-Adapter. Beleg via ``id()``-Probe: der von
``provide_run_arp_scan`` gebaute RunArpScan teilt das ``arp_table``/``vendor_lookup``
mit dem von ``provide_get_arp_table``/``provide_lookup_vendor`` gebauten scanning-UC.
"""

from api.scanning import provide_get_arp_table, provide_lookup_vendor
from api.security import provide_run_arp_scan
from app import create_app
from infrastructure.config import AppConfig


def test_run_arp_scan_reuses_scanning_adapters() -> None:
    app = create_app(AppConfig())  # bootstrap_on_startup=False (kein echter Effekt)

    run_arp_scan = app.dependency_overrides[provide_run_arp_scan]()
    get_arp_table = app.dependency_overrides[provide_get_arp_table]()
    lookup_vendor = app.dependency_overrides[provide_lookup_vendor]()

    # RunArpScan haelt arp_table/vendor_lookup als private Attribute (SEC.5-ctor).
    # GetArpTable/LookupVendor (scanning) halten dieselben Adapter -- id()-Gleichheit
    # beweist die Wiederverwendung (kein zweiter Adapter instanziiert).
    assert run_arp_scan._arp_table is get_arp_table._arp_table
    assert run_arp_scan._vendor_lookup is lookup_vendor._vendor_lookup


def test_security_routes_registered() -> None:
    app = create_app(AppConfig())
    paths = {route.path for route in app.routes}  # type: ignore[attr-defined]
    assert "/api/security/arp-scan" in paths
    assert "/api/security/arp-alerts" in paths
    assert "/api/security/arp-baseline" in paths
    assert "/api/cve/lookup-v2" in paths
    assert "/api/tls/inspect-host" in paths
    assert "/api/security/default-creds" in paths
    # tote Endpunkte NICHT registriert (bewusste Streichung).
    assert "/api/cve/lookup" not in paths
    assert "/api/tls/inspect" not in paths
