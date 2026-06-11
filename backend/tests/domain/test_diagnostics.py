"""Unit-Tests der diagnostics-Domaene -- reine Wertobjekte + ``dedup_records``.

Prueft die frozen-Semantik der Wertobjekte, die ehrliche None-Naht des nicht-antwortenden
traceroute-Hops und die leere DNS-Antwort, sowie die reine Funktion ``dedup_records``
(Dedup ueber (Typ, Wert), deterministische Sortierung). Alle Werte kommen als Felder
herein -> rein deterministisch, kein I/O, keine Uhr.
"""

import pytest

from domain.diagnostics import (
    ALL_TOOLS,
    TOOL_PACKAGES,
    BannerResult,
    DnsRecord,
    DnsResult,
    ToolReport,
    ToolStatus,
    TracerouteHop,
    TracerouteResult,
    assemble_report,
    build_install_command,
    dedup_records,
    probe_for_port,
    sanitize_banner,
)

# ── Wertobjekte (frozen + ehrliche None-Naht) ─────────────────────────────────


def test_dns_record_is_frozen() -> None:
    rec = DnsRecord(record_type="A", value="1.2.3.4")
    with pytest.raises(AttributeError):
        rec.value = "9.9.9.9"  # type: ignore[misc]


def test_dns_result_empty_records_is_not_an_error() -> None:
    # Leere records = keine Antwort (NXDOMAIN/kein Eintrag), KEIN Fehler.
    result = DnsResult(query="nope.invalid", requested_types=("A",), records=())
    assert result.records == ()
    assert result.requested_types == ("A",)


def test_traceroute_hop_non_responding_is_honest_none() -> None:
    # Ein nicht-antwortender Hop (Timeout/``*``) -> address/rtt_ms ehrlich None.
    hop = TracerouteHop(hop=7, address=None, rtt_ms=None)
    assert hop.hop == 7
    assert hop.address is None
    assert hop.rtt_ms is None


def test_traceroute_hop_is_frozen() -> None:
    hop = TracerouteHop(hop=1, address="1.2.3.4", rtt_ms=0.5)
    with pytest.raises(AttributeError):
        hop.rtt_ms = 1.0  # type: ignore[misc]


def test_traceroute_result_carries_privileged_flag() -> None:
    # privileged spiegelt ehrlich, WIE gemessen wurde.
    result = TracerouteResult(target="example.com", privileged=True, hops=())
    assert result.privileged is True
    assert result.target == "example.com"
    assert result.hops == ()


# ── dedup_records (rein, deterministisch, mutationsprobe-tauglich) ─────────────


def test_dedup_records_empty() -> None:
    assert dedup_records([]) == ()


def test_dedup_records_removes_duplicate_type_value_pairs() -> None:
    # Zweimal derselbe (Typ, Wert) -> nur EIN Eintrag.
    records = [
        DnsRecord(record_type="A", value="1.2.3.4"),
        DnsRecord(record_type="A", value="1.2.3.4"),
    ]
    assert dedup_records(records) == (DnsRecord(record_type="A", value="1.2.3.4"),)


def test_dedup_records_keeps_same_value_different_type() -> None:
    # Gleicher Wert, anderer Typ -> KEIN Duplikat (beide bleiben).
    records = [
        DnsRecord(record_type="A", value="1.2.3.4"),
        DnsRecord(record_type="PTR", value="1.2.3.4"),
    ]
    result = dedup_records(records)
    assert len(result) == 2


def test_dedup_records_sorts_deterministically() -> None:
    # Eingangsreihenfolge bewusst durcheinander; Ergebnis aufsteigend nach (Typ, Wert).
    records = [
        DnsRecord(record_type="A", value="9.9.9.9"),
        DnsRecord(record_type="AAAA", value="::1"),
        DnsRecord(record_type="A", value="1.1.1.1"),
    ]
    result = dedup_records(records)
    assert result == (
        DnsRecord(record_type="A", value="1.1.1.1"),
        DnsRecord(record_type="A", value="9.9.9.9"),
        DnsRecord(record_type="AAAA", value="::1"),
    )


def test_dedup_records_first_occurrence_wins_identity() -> None:
    # Bei Duplikat gewinnt das erste Vorkommen die Identitaet (hier wertgleich, aber
    # belegt, dass kein zweiter Eintrag durchrutscht -- Mutationsprobe gegen ">= statt >").
    records = [
        DnsRecord(record_type="MX", value="10 a.example."),
        DnsRecord(record_type="MX", value="10 a.example."),
        DnsRecord(record_type="MX", value="20 b.example."),
    ]
    result = dedup_records(records)
    assert result == (
        DnsRecord(record_type="MX", value="10 a.example."),
        DnsRecord(record_type="MX", value="20 b.example."),
    )


# ── Block 1b: Registry (einzige Quelle der Wahrheit) ──────────────────────────


def test_all_tools_is_sorted_and_derived_from_registry() -> None:
    # ALL_TOOLS ist deterministisch sortiert und deckt sich mit den Registry-Keys.
    assert ALL_TOOLS == ("dig", "traceroute")
    assert set(ALL_TOOLS) == set(TOOL_PACKAGES.keys())


def test_tool_status_is_frozen() -> None:
    status = ToolStatus(name="dig", available=True)
    with pytest.raises(AttributeError):
        status.available = False  # type: ignore[misc]


def test_tool_report_is_frozen() -> None:
    report = ToolReport(manager=None, statuses=(), install_command=None)
    with pytest.raises(AttributeError):
        report.manager = "apt"  # type: ignore[misc]


# ── build_install_command (heikelste Stelle: Paketnamen je Manager) ───────────


def test_build_install_command_apt_dig_is_dnsutils() -> None:
    # apt: dig steckt im Paket ``dnsutils`` (NICHT bind-utils) -- der entscheidende Unterschied.
    cmd = build_install_command("apt", ["dig"])
    assert cmd == "sudo apt install dnsutils"


def test_build_install_command_dnf_dig_is_bind_utils() -> None:
    cmd = build_install_command("dnf", ["dig"])
    assert cmd == "sudo dnf install bind-utils"


def test_build_install_command_yum_matches_dnf_package_names() -> None:
    # yum mappt bewusst auf dieselben Paketnamen wie dnf (RHEL-Altsysteme).
    assert build_install_command("yum", ["dig"]) == "sudo yum install bind-utils"
    assert build_install_command("yum", ["traceroute"]) == "sudo yum install traceroute"


def test_build_install_command_zypper_dig_is_bind_utils() -> None:
    cmd = build_install_command("zypper", ["dig"])
    assert cmd == "sudo zypper install bind-utils"


def test_build_install_command_pacman_uses_dash_s_and_bind() -> None:
    # pacman: ``-S`` statt ``install`` UND dig steckt im Paket ``bind``.
    cmd = build_install_command("pacman", ["dig"])
    assert cmd == "sudo pacman -S bind"


def test_build_install_command_traceroute_same_name_everywhere() -> None:
    # traceroute heisst ueberall ``traceroute`` -- nur das Befehls-Schema unterscheidet sich.
    assert build_install_command("apt", ["traceroute"]) == "sudo apt install traceroute"
    assert build_install_command("pacman", ["traceroute"]) == "sudo pacman -S traceroute"


def test_build_install_command_manager_none_returns_none() -> None:
    # Kein bekannter Manager -> None, KEIN geratener Befehl.
    assert build_install_command(None, ["dig", "traceroute"]) is None


def test_build_install_command_no_missing_returns_none() -> None:
    # Nichts fehlt -> None (es gibt nichts zu installieren).
    assert build_install_command("apt", []) is None


def test_build_install_command_dedups_and_sorts_packages() -> None:
    # Mehrere Tools, deren Pakete teils gleich heissen: dedup + deterministische Sortierung.
    # apt: dig->dnsutils, traceroute->traceroute -> aufsteigend: dnsutils traceroute.
    cmd = build_install_command("apt", ["traceroute", "dig", "dig"])
    assert cmd == "sudo apt install dnsutils traceroute"


def test_build_install_command_skips_unknown_tool() -> None:
    # Ein unbekanntes Tool wird uebersprungen (nicht erfunden) -- nur das bekannte zaehlt.
    cmd = build_install_command("apt", ["dig", "nmap"])
    assert cmd == "sudo apt install dnsutils"


def test_build_install_command_only_unknown_returns_none() -> None:
    # Nur unbekannte Tools -> keine Pakete uebrig -> None (kein leerer Befehl).
    assert build_install_command("apt", ["nmap", "curl"]) is None


# ── assemble_report ───────────────────────────────────────────────────────────


def test_assemble_report_statuses_sorted_by_name() -> None:
    # Eingangsreihenfolge bewusst verdreht; statuses aufsteigend nach name.
    report = assemble_report("apt", {"traceroute": True, "dig": False}, ["traceroute", "dig"])
    assert report.statuses == (
        ToolStatus(name="dig", available=False),
        ToolStatus(name="traceroute", available=True),
    )


def test_assemble_report_missing_drives_install_command() -> None:
    # dig fehlt, traceroute da -> install_command nur fuer dig (apt: dnsutils).
    report = assemble_report("apt", {"dig": False, "traceroute": True}, ["dig", "traceroute"])
    assert report.manager == "apt"
    assert report.install_command == "sudo apt install dnsutils"


def test_assemble_report_nothing_missing_no_command() -> None:
    # Alles da -> install_command None (nichts zu installieren), Manager trotzdem gefuehrt.
    report = assemble_report("dnf", {"dig": True, "traceroute": True}, ["dig", "traceroute"])
    assert report.install_command is None
    assert report.manager == "dnf"


def test_assemble_report_manager_none_command_none() -> None:
    # Tool fehlt, aber kein Manager bekannt -> install_command ehrlich None (kein Raten).
    report = assemble_report(None, {"dig": False}, ["dig"])
    assert report.manager is None
    assert report.install_command is None
    assert report.statuses == (ToolStatus(name="dig", available=False),)


def test_assemble_report_unknown_availability_defaults_false() -> None:
    # Fehlt der Verfuegbarkeits-Eintrag, gilt das Tool defensiv als nicht verfuegbar.
    report = assemble_report("apt", {}, ["dig"])
    assert report.statuses == (ToolStatus(name="dig", available=False),)
    assert report.install_command == "sudo apt install dnsutils"


# ── Block 2a: probe_for_port (einzige Heuristik, mutationsproben-tauglich) ─────


def test_probe_for_port_plaintext_web_ports_are_http_head() -> None:
    # Die Klartext-Web-Ports -> http_head (minimale HTTP-HEAD-Anfrage).
    for port in (80, 8080, 8000, 8008):
        assert probe_for_port(port) == "http_head"


def test_probe_for_port_other_ports_are_passive() -> None:
    # Nicht-Web-Ports -> passive (der Dienst gruesst selbst).
    for port in (22, 25, 21, 3306, 6379, 12345):
        assert probe_for_port(port) == "passive"


def test_probe_for_port_tls_ports_are_passive_not_http_head() -> None:
    # TLS-Ports {443, 8443} sind BEWUSST passive (kein TLS-Handshake in 2a) -- ein roher
    # Connect spraeche TLS, kein Klartext-HTTP. Mutationsprobe gegen "443 in http_head-Menge".
    assert probe_for_port(443) == "passive"
    assert probe_for_port(8443) == "passive"


# ── Block 2a: sanitize_banner (erste Zeile, Steuerzeichen raus, gekuerzt) ──────


def test_sanitize_banner_keeps_first_line_only() -> None:
    # Mehrzeilige Antwort -> nur die erste Zeile (ein Banner ist eine Begruessungszeile).
    assert sanitize_banner("SSH-2.0-OpenSSH_9.6\r\nzweite Zeile") == "SSH-2.0-OpenSSH_9.6"


def test_sanitize_banner_strips_control_characters() -> None:
    # Steuerzeichen (Tab, \x00, ESC) raus; nur druckbarer Text bleibt.
    assert sanitize_banner("220\x00 smtp\x1b ready\t!") == "220 smtp ready!"


def test_sanitize_banner_truncates_to_max_length() -> None:
    # Eine uferlose Antwort wird auf 512 Zeichen gekuerzt. Mutationsprobe: Kuerzung raus -> rot.
    raw = "x" * 1000
    result = sanitize_banner(raw)
    assert len(result) == 512
    assert result == "x" * 512


def test_sanitize_banner_empty_input() -> None:
    # Leere Eingabe -> leerer String (der Adapter leitet daraus no_banner ab).
    assert sanitize_banner("") == ""


def test_sanitize_banner_only_control_chars_becomes_empty() -> None:
    # Eine Zeile nur aus Steuerzeichen -> leer (kein erfundener Banner).
    assert sanitize_banner("\x00\x01\x02") == ""


# ── Block 2a: BannerResult (frozen + ehrliche None-Naht) ──────────────────────


def test_banner_result_is_frozen() -> None:
    result = BannerResult(
        target="example.com", port=22, probe="passive", banner="SSH-2.0", state="ok"
    )
    with pytest.raises(AttributeError):
        result.banner = "anders"  # type: ignore[misc]


def test_banner_result_no_banner_is_honest_none() -> None:
    # Verbunden, aber keine lesbare Antwort -> banner ehrlich None, state no_banner.
    result = BannerResult(
        target="example.com", port=443, probe="passive", banner=None, state="no_banner"
    )
    assert result.banner is None
    assert result.state == "no_banner"
