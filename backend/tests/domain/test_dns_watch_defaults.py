"""Tests fuer die reine Default-Listen-Logik des DNS-Waechters (Block 2, 2d).

Belegt beide Funktionen: erwartet sind GENAU die konfigurierten Server (leer ->
leeres Tupel, KEIN Gateway-Fallback mehr, D4) sowie das Greifen der
DoH-Startliste. Reine Funktionen -- kein I/O, keine Fixtures noetig.
"""

from domain.dns_watch import (
    DEFAULT_DOH_PROVIDER_IPS,
    doh_providers_or_default,
    expected_servers_or_default,
)

# ── expected_servers_or_default ───────────────────────────────────────────────


def test_expected_ist_genau_die_konfigurierte_liste() -> None:
    assert expected_servers_or_default(["192.168.0.1", "10.0.0.1"]) == (
        "192.168.0.1",
        "10.0.0.1",
    )


def test_expected_leer_bleibt_leer_kein_gateway_fallback() -> None:
    # D4: leere Konfiguration -> leeres Tupel; jede Port-53-Verbindung gilt dann
    # ehrlich als "offen", es wird KEIN Gateway mehr als erwartet vermutet.
    assert expected_servers_or_default([]) == ()


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
