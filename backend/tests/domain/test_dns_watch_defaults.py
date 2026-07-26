"""Tests fuer die reine Default-Listen-Logik des DNS-Waechters (Block 2, 2d).

Belegt das Greifen der DoH-Startliste. Reine Funktion -- kein I/O, keine Fixtures noetig.

Die frueher hier ebenfalls belegte ``expected_servers_or_default`` ist mit S62 L7a
ENTFALLEN (samt ihrer Tests, insbesondere dem, der "leere Liste bleibt leer"
festschrieb): die erwartete DNS-Server-Menge kommt nicht mehr aus einem
Einstellungs-Schluessel, sondern aus dem Vertrauensmodell. Sie wird jetzt in
``tests/application/dns_trust/test_use_cases.py`` (``TrustedDnsServerIps``) belegt.
"""

from domain.dns_watch import (
    DEFAULT_DOH_PROVIDER_IPS,
    doh_providers_or_default,
)

# ── doh_providers_or_default ──────────────────────────────────────────────────


def test_doh_configured_gewinnt() -> None:
    assert doh_providers_or_default(["1.1.1.1"]) == ("1.1.1.1",)


def test_doh_leer_greift_default_startliste() -> None:
    assert doh_providers_or_default([]) == DEFAULT_DOH_PROVIDER_IPS


def test_doh_default_enthaelt_bekannte_anbieter() -> None:
    # Stichprobe je Anbieter (IPv4 + IPv6), damit die Startliste nicht versehentlich
    # schrumpft.
    assert "1.1.1.1" in DEFAULT_DOH_PROVIDER_IPS
    assert "2606:4700:4700::1111" in DEFAULT_DOH_PROVIDER_IPS
    assert "8.8.8.8" in DEFAULT_DOH_PROVIDER_IPS
    assert "2001:4860:4860::8888" in DEFAULT_DOH_PROVIDER_IPS
    assert "9.9.9.9" in DEFAULT_DOH_PROVIDER_IPS
    assert "2620:fe::fe" in DEFAULT_DOH_PROVIDER_IPS
