"""Tests des eingebauten DoH-Werkslisten-Inhalts (Etappe 3).

Belegt, dass die zwei Text-Konstanten ueber ``parse_blocklist`` zu nicht-leeren Listen
zerfallen, den Kern-Satz ``DEFAULT_DOH_PROVIDER_IPS`` als Basis fuehren (EINE Quelle der
Wahrheit) und die erwarteten DoH-Endpunkt-Hostnamen enthalten.
"""

from application.blocklist.doh_builtin import BUILTIN_DOH_CONTENT
from application.blocklist.parsing import parse_blocklist
from domain.blocklist import BlocklistFormat
from domain.dns_watch.defaults import DEFAULT_DOH_PROVIDER_IPS


def test_builtin_doh_ip_parst_und_enthaelt_kern_ips() -> None:
    _, ip_cidrs = parse_blocklist(BlocklistFormat.IP_LIST, BUILTIN_DOH_CONTENT["doh_providers_ip"])
    assert ip_cidrs  # nicht leer
    # Die Kern-IPs des host-lokalen Waechters sind Basis -> muessen enthalten sein.
    for kern_ip in DEFAULT_DOH_PROVIDER_IPS:
        assert kern_ip in ip_cidrs


def test_builtin_doh_domain_parst_und_enthaelt_bekannte_endpunkte() -> None:
    domains, _ = parse_blocklist(
        BlocklistFormat.DOMAIN_LIST, BUILTIN_DOH_CONTENT["doh_providers_domain"]
    )
    assert domains  # nicht leer
    assert "cloudflare-dns.com" in domains
    assert "dns.google" in domains
