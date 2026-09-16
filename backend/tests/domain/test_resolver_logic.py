"""Unit-Tests der resolver-Domaene -- die vier reinen Funktionen aus ``logic.py``.

Prueft den Anti-Spoof-Abgleich (``confirm_forward``), das Aufzeigen von Laender-
Widerspruechen (``flag_country_conflict``: 2 vs. 3 Quellen, None-Mischung, Normalisierung),
die Feststellung self-signed (``detect_self_signed``: True/False/None) und den lokalen
Port->Dienst-Hinweis (``service_hint_for_port``: bekannt/unbekannt/None). Alles rein
deterministisch -- kein I/O, keine Uhr. Port-Tests entfallen (reine Protocols).
"""

from domain.resolver import (
    confirm_forward,
    derive_dyndns,
    detect_self_signed,
    flag_country_conflict,
    service_hint_for_port,
)


class TestConfirmForward:
    def test_hit_bestaetigt(self) -> None:
        assert confirm_forward(("1.2.3.4", "5.6.7.8"), "5.6.7.8") is True

    def test_miss_nicht_bestaetigt(self) -> None:
        assert confirm_forward(("1.2.3.4", "5.6.7.8"), "9.9.9.9") is False

    def test_leere_vorwaerts_liste(self) -> None:
        assert confirm_forward((), "5.6.7.8") is False

    def test_einziger_treffer(self) -> None:
        assert confirm_forward(("5.6.7.8",), "5.6.7.8") is True


class TestFlagCountryConflict:
    def test_zwei_quellen_widerspruch(self) -> None:
        assert flag_country_conflict("DE", "US", None) is True

    def test_zwei_quellen_einig(self) -> None:
        assert flag_country_conflict("DE", "DE", None) is False

    def test_drei_quellen_widerspruch(self) -> None:
        assert flag_country_conflict("DE", "US", "FR") is True

    def test_drei_quellen_einig(self) -> None:
        assert flag_country_conflict("DE", "DE", "DE") is False

    def test_drei_quellen_einer_weicht_ab(self) -> None:
        assert flag_country_conflict("DE", "DE", "US") is True

    def test_eine_einzige_bekannte_quelle_kein_konflikt(self) -> None:
        assert flag_country_conflict("DE", None, None) is False

    def test_keine_bekannte_quelle_kein_konflikt(self) -> None:
        assert flag_country_conflict(None, None, None) is False

    def test_normalisierung_grossschreibung_und_whitespace(self) -> None:
        # "DE" und " de " gelten als gleich -> kein Konflikt.
        assert flag_country_conflict("DE", " de ", None) is False

    def test_none_mischung_mit_widerspruch(self) -> None:
        assert flag_country_conflict(None, "DE", "US") is True

    def test_none_mischung_einig(self) -> None:
        assert flag_country_conflict(None, "DE", "de") is False


class TestDetectSelfSigned:
    def test_subject_gleich_issuer_true(self) -> None:
        assert detect_self_signed("example.org", "example.org") is True

    def test_subject_ungleich_issuer_false(self) -> None:
        assert detect_self_signed("example.org", "Some CA") is False

    def test_subject_fehlt_none(self) -> None:
        assert detect_self_signed(None, "Some CA") is None

    def test_issuer_fehlt_none(self) -> None:
        assert detect_self_signed("example.org", None) is None

    def test_beide_fehlen_none(self) -> None:
        assert detect_self_signed(None, None) is None


class TestDeriveDyndns:
    def test_ptr_treffer_je_suffix(self) -> None:
        # Ein PTR-Name je gaengigem Suffix -> erkannt (normalisiert kleingeschrieben).
        assert derive_dyndns("box.dyndns.org", None) == "box.dyndns.org"
        assert derive_dyndns("foo.no-ip.com", None) == "foo.no-ip.com"
        assert derive_dyndns("home.ddns.net", None) == "home.ddns.net"
        assert derive_dyndns("a.dyn.com", None) == "a.dyn.com"
        assert derive_dyndns("nas.spdns.de", None) == "nas.spdns.de"
        assert derive_dyndns("xyz.myfritz.net", None) == "xyz.myfritz.net"
        assert derive_dyndns("h.dynv6.net", None) == "h.dynv6.net"
        assert derive_dyndns("pi.duckdns.org", None) == "pi.duckdns.org"

    def test_tls_cn_treffer_wenn_ptr_leer(self) -> None:
        # Kein PTR, aber der TLS-CN endet auf ein DynDNS-Suffix -> erkannt.
        assert derive_dyndns(None, "host.no-ip.com") == "host.no-ip.com"
        assert derive_dyndns("", "host.ddns.net") == "host.ddns.net"

    def test_ptr_vor_tls_cn(self) -> None:
        # Beide treffen -> der PTR-Kandidat gewinnt (zuerst geprueft).
        assert derive_dyndns("a.dyndns.org", "b.no-ip.com") == "a.dyndns.org"

    def test_nackte_suffix_domain_trifft(self) -> None:
        # Der Name IST exakt das Suffix (ohne Subdomain) -> ebenfalls Treffer.
        assert derive_dyndns("dyndns.org", None) == "dyndns.org"

    def test_normalisierung_grossschreibung_und_punkt(self) -> None:
        # Grossschreibung + abschliessender Wurzel-Punkt -> normalisiert kleingeschrieben.
        assert derive_dyndns("BOX.DynDNS.org.", None) == "box.dyndns.org"

    def test_kein_treffer_gewoehnliche_domain(self) -> None:
        assert derive_dyndns("mail.example.com", "www.example.com") is None

    def test_suffix_nur_als_teilstring_kein_treffer(self) -> None:
        # "notdyndns.org" enthaelt "dyndns.org" als Teilstring, endet aber nicht als
        # eigenes Label darauf -> KEIN Treffer (kein naives "in").
        assert derive_dyndns("notdyndns.org", None) is None

    def test_leere_eingaben_none(self) -> None:
        assert derive_dyndns(None, None) is None
        assert derive_dyndns("", "") is None


class TestServiceHintForPort:
    def test_bekannter_port_https(self) -> None:
        assert service_hint_for_port(443) == "https"

    def test_bekannter_port_ssh(self) -> None:
        assert service_hint_for_port(22) == "ssh"

    def test_bekannter_port_https_alt(self) -> None:
        assert service_hint_for_port(8443) == "https-alt"

    def test_unbekannter_port_none(self) -> None:
        assert service_hint_for_port(12345) is None

    def test_none_port_none(self) -> None:
        assert service_hint_for_port(None) is None
