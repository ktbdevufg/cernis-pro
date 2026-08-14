"""Unit-Tests der scanning-Domaenenmodelle -- reine Logik, kein I/O."""

import dataclasses
import time
import tracemalloc

import pytest

from domain.scanning import (
    MAX_SCAN_ADRESSEN,
    DiscoveredHost,
    EnrichedHost,
    HostClassification,
    NetzZuGrossError,
    PortInfo,
    ScanConfig,
)

# ── ScanConfig ───────────────────────────────────────────────────────────────


def test_scan_config_defaults() -> None:
    cfg = ScanConfig(cidrs=("192.168.1.0/24",))
    assert cfg.ping_timeout == 1.5
    assert cfg.port_scan is True
    assert cfg.port_mode == "socket"
    assert cfg.mdns_scan is True
    assert cfg.mdns_duration == 8.0
    assert cfg.resolve_hostnames is True
    assert cfg.smb_scan is False
    assert cfg.ssdp_scan is True
    assert cfg.max_concurrent_ping == 64
    assert cfg.max_concurrent_ports == 100
    assert cfg.custom_ports is None


def test_scan_config_accepts_multiple_cidrs() -> None:
    # Zwei /24 statt des frueheren "10.0.0.0/8": dieser Test prueft, dass MEHRERE
    # CIDRs angenommen werden -- nicht ihre Groesse. Seit der Netzgroessen-Schranke
    # (S88-P2) liegt ein /8 ueber der Obergrenze; die Aussage des Tests bleibt
    # unveraendert, nur die Kulisse ist jetzt eine, die der Scanner auch annimmt.
    cfg = ScanConfig(cidrs=("192.168.1.0/24", "10.0.0.0/24"))
    assert cfg.cidrs == ("192.168.1.0/24", "10.0.0.0/24")


def test_scan_config_empty_cidrs_raises() -> None:
    with pytest.raises(ValueError):
        ScanConfig(cidrs=())


def test_scan_config_invalid_cidr_raises() -> None:
    with pytest.raises(ValueError, match="Invalid CIDR"):
        ScanConfig(cidrs=("nonsense",))


def test_scan_config_nonpositive_timeout_raises() -> None:
    with pytest.raises(ValueError):
        ScanConfig(cidrs=("192.168.1.0/24",), ping_timeout=0)


def test_scan_config_nonpositive_concurrency_raises() -> None:
    with pytest.raises(ValueError):
        ScanConfig(cidrs=("192.168.1.0/24",), max_concurrent_ping=0)


# ── Netzgroessen-Obergrenze (S88-P2) ─────────────────────────────────────────


def test_grenzwert_ist_4096() -> None:
    """Die Konstante traegt Karls Beschluss aus Sitzung 86: 4096 = ein /20."""
    assert MAX_SCAN_ADRESSEN == 4096


def test_genau_4096_adressen_werden_angenommen() -> None:
    """4.1: Ein /20 sind genau 4096 Adressen -- die Grenze selbst ist erlaubt."""
    cfg = ScanConfig(cidrs=("10.0.0.0/20",))
    assert cfg.cidrs == ("10.0.0.0/20",)


def test_4097_adressen_werden_abgelehnt() -> None:
    """4.2: Eine Adresse ueber der Grenze reicht zur Ablehnung.

    4097 laesst sich nicht als EIN Praefix ausdruecken (Zweierpotenzen), darum ein
    /20 plus ein /32 -- zusammen genau 4097. Das prueft die Grenze auf die Adresse
    genau, nicht bloss die naechste Praefixstufe.
    """
    with pytest.raises(NetzZuGrossError) as exc_info:
        ScanConfig(cidrs=("10.0.0.0/20", "192.168.5.7/32"))
    assert exc_info.value.anzahl == 4097


def test_zwei_netze_je_unter_der_grenze_zusammen_darueber_werden_abgelehnt() -> None:
    """4.3 (der tragende Test): gezaehlt wird die SUMME, nicht je Netz.

    Zwei /21 sind einzeln je 2048 Adressen -- jedes fuer sich klar unter der Grenze
    und einzeln anstandslos erlaubt (das belegt der zweite Teil des Tests). Zusammen
    mit einem /24 sind es 4352 und damit darueber. Eine Grenze JE NETZ liesse das
    durch; die Summenrechnung faengt es.
    """
    # Jedes der drei Netze ist FUER SICH erlaubt -- sonst pruefte der Test unten
    # nicht die Summe, sondern bloss ein zu grosses Einzelnetz.
    ScanConfig(cidrs=("10.0.0.0/21",))
    ScanConfig(cidrs=("10.1.0.0/21",))
    ScanConfig(cidrs=("10.2.0.0/24",))

    with pytest.raises(NetzZuGrossError) as exc_info:
        ScanConfig(cidrs=("10.0.0.0/21", "10.1.0.0/21", "10.2.0.0/24"))
    assert exc_info.value.anzahl == 4352


def test_zwanzig_kleine_netze_zusammen_unter_der_grenze_werden_angenommen() -> None:
    """4.4: Viele Einzelnetze sind erlaubt, solange die SUMME passt.

    Zwanzig /24 = 5120 Adressen waeren zu viel; zwanzig /25 = 2560 passen. Der Test
    belegt, dass nicht die ANZAHL der Netze begrenzt ist, sondern ihre Summe.
    """
    cidrs = tuple(f"10.0.{i}.0/25" for i in range(20))
    cfg = ScanConfig(cidrs=cidrs)
    assert len(cfg.cidrs) == 20


def test_ueberlappende_netze_werden_nicht_entdoppelt() -> None:
    """1.4: Ein Netz zaehlt so oft, wie es angegeben ist.

    Zweimal DASSELBE /20 sind 8192 gezaehlte Adressen, nicht 4096. Eine Entdopplung
    waere eine Rechnung, die der Anwender nicht nachvollziehen kann.
    """
    with pytest.raises(NetzZuGrossError) as exc_info:
        ScanConfig(cidrs=("10.0.0.0/20", "10.0.0.0/20"))
    assert exc_info.value.anzahl == 8192


def test_fehlermeldung_traegt_die_richtige_gesamtzahl() -> None:
    """4.5: Die gemessene Summe haengt als ATTRIBUT an der Ausnahme.

    Als Attribut, nicht als zu parsender Text (Muster KeyMissingError.key_file,
    Befund 65) -- der Rand nennt die Zahl ohne Text-Parsen. Der Text selbst ist
    englischer ENTWICKLERtext und traegt sie nur zur Diagnose mit.
    """
    with pytest.raises(NetzZuGrossError) as exc_info:
        ScanConfig(cidrs=("10.0.0.0/16",))
    fehler = exc_info.value
    assert fehler.anzahl == 65536
    assert fehler.maximum == 4096
    assert "65536" in str(fehler)


def test_netz_zu_gross_ist_ein_value_error() -> None:
    """1.5: Subtyp von ValueError -- der belegte Weg bis zur Oberflaeche traegt.

    Jeder bestehende ``except ValueError`` am Rand faengt die Ausnahme unveraendert
    weiter; ein Pfad, der sie nicht gesondert behandelt, zeigt den Entwicklertext
    statt eines uebersetzten -- aber stuerzt nie ab.
    """
    assert issubclass(NetzZuGrossError, ValueError)
    with pytest.raises(ValueError, match="Network too large"):
        ScanConfig(cidrs=("10.0.0.0/8",))


def test_uebliches_heimnetz_bleibt_unberuehrt() -> None:
    """4.6: Der Normalfall (/24, 256 Adressen) laeuft wie zuvor durch."""
    cfg = ScanConfig(cidrs=("192.168.1.0/24",))
    assert cfg.cidrs == ("192.168.1.0/24",)


def test_grosses_netz_wird_ohne_materialisierung_abgelehnt() -> None:
    """4.7: Gezaehlt wird ueber ``num_addresses``, NICHT ueber ``hosts()``.

    Ein /8 sind 16.777.216 Adressen. ``num_addresses`` ist eine reine Rechnung aus
    der Praefixlaenge -- Aufwand und Speicher haengen NICHT an der Netzgroesse.

    Zwei Schranken, weil das Aufzaehlen sich in BEIDEN Groessen zeigt:

    * SPEICHER -- gemessen als Unterschied zum /24-Fall. Ein materialisiertes
      ``list(hosts())`` waere hier dreistellige Megabyte; die Schranke (100 KiB) ist
      bewusst grosszuegig, sie soll das Aufzaehlen fangen, nicht das Rauschen des
      Interpreters messen.
    * LAUFZEIT -- die schaerfere der beiden: ``hosts()`` ist ein GENERATOR, ein
      blosses Durchzaehlen bliebe also speicherarm, kostete aber Zeit proportional
      zur Netzgroesse (gemessen: 44,6 ms je /16, also ~11 s fuer ein /8). Ohne diese
      zweite Schranke ginge ein ``sum(1 for _ in netz.hosts())`` unbemerkt durch.
      100 ms sind drei Groessenordnungen ueber der echten Messung (0,036 ms) und
      zwei unter dem Aufzaehl-Fall.
    """
    tracemalloc.start()
    try:
        # Referenz: der Normalfall, der garantiert nichts materialisiert.
        tracemalloc.reset_peak()
        ScanConfig(cidrs=("192.168.1.0/24",))
        _, klein_peak = tracemalloc.get_traced_memory()

        # Der Ablehnungsfall ueber ein /8 (16.777.216 Adressen).
        tracemalloc.reset_peak()
        beginn = time.perf_counter()
        with pytest.raises(NetzZuGrossError) as exc_info:
            ScanConfig(cidrs=("10.0.0.0/8",))
        dauer = time.perf_counter() - beginn
        _, gross_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert exc_info.value.anzahl == 16777216
    assert gross_peak - klein_peak < 100 * 1024, (
        f"Ablehnung eines /8 kostete {gross_peak - klein_peak} Bytes mehr als ein "
        f"/24 -- das deutet auf Materialisierung (list(hosts())) hin."
    )
    assert dauer < 0.1, (
        f"Ablehnung eines /8 dauerte {dauer:.3f} s -- das deutet auf ein Durchzaehlen "
        f"(hosts()) statt auf num_addresses hin."
    )


# ── EnrichedHost / PortInfo / DiscoveredHost / HostClassification ────────────


def test_enriched_host_tuples_stay_tuples() -> None:
    host = EnrichedHost(
        ip="192.168.1.2",
        mac="AA:BB:CC:DD:EE:01",
        ports=(PortInfo(port=22, state="open", service="SSH"),),
        tags=("prod", "core"),
    )
    assert isinstance(host.ports, tuple)
    assert isinstance(host.tags, tuple)
    assert host.ports[0].port == 22
    assert host.os_accuracy == 0
    assert host.scan_method == "socket"
    # IPv6-Anreicherungsfelder (S.4e-Vorbau): Defaults leer, ipv6_all ist tuple.
    assert host.ipv6 == ""
    assert host.ipv6_all == ()
    assert isinstance(host.ipv6_all, tuple)


def test_host_classification_fields() -> None:
    classification = HostClassification(os_guess="Linux Server", category="server")
    assert classification.os_guess == "Linux Server"
    assert classification.category == "server"


def test_models_are_frozen() -> None:
    host = DiscoveredHost(ip="192.168.1.2")
    # Attributname als Variable: vermeidet ruff B010 und den mypy-Frozen-Schreibfehler
    # eines direkten host.ip = ... (frozen wird zur Laufzeit geprueft).
    field_name = "ip"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(host, field_name, "10.0.0.1")
