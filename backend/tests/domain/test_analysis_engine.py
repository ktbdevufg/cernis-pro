"""Unit-Tests der analysis-RuleEngine -- reine Logik, kein I/O, keine Uhr.

Prueft, dass ``evaluate`` deterministisch ist, jede Start-Regel (``DEFAULT_RULES``) bei
passender Eingabe genau die erwartete ``Observation`` erzeugt und bei unpassender KEINE,
ein leerer Snapshot ``[]`` liefert und die Sortierung stabil ist. Alle Werte kommen als
Felder herein -> rein deterministisch.

KERNFIX AN.3: echte Kernel-Threads (``kind == "kernel"``) erzeugen NIE eine
process-Beobachtung -- ihr fehlender ``exe_path``/leeres ``cmdline`` ist Natur, kein
Verhalten. Userland-Auffaelligkeiten werden differenziert gezeigt: temp-Pfad (notable) vs.
Tarnverdacht (info, leeres cmdline ODER fehlender Pfad).

MUTATIONSPROBEN (durchgefuehrt waehrend der Entwicklung, hier dokumentiert): Fuer jede
Regel wurde EINE Mutation am Domaenen-Code probiert und ROT bestaetigt, dann
zurueckgesetzt -- der Test faengt den jeweiligen kritischen Vertrag also wirklich:

* (kind-Filter) ``if proc.kind == "kernel": continue`` in ``_eval_process_masquerade``
  ENTFERNT -> ``test_kernel_thread_erzeugt_keine_beobachtung`` ROT (der kernel-Thread mit
  leerem cmdline + None-Pfad wuerde faelschlich als Tarnverdacht treffen). Zurueckgesetzt.
* (AN.3-fix-2: Rechte-Waechter) ``snapshot.full_process_visibility`` aus dem (ii)-Zweig
  von ``_eval_process_masquerade`` ENTFERNT (``if path is None:`` statt
  ``if path is None and snapshot.full_process_visibility:``) ->
  ``test_masquerade_kein_pfad_rootless_schweigt`` ROT (der fehlende Pfad trifft auch
  rootless). Zurueckgesetzt.
* (a) process_temp_path: Pfad-Praefix ``/tmp/`` aus ``DEFAULT_RULES`` entfernt
  -> ``test_rule_a_tmp_pfad_trifft`` ROT (der /tmp-Treffer entfaellt). Zurueckgesetzt.
* (b) remote_access_port: Portmenge in ``DEFAULT_RULES`` geleert (``frozenset()``)
  -> ``test_rule_b_*`` ROT (kein Port trifft mehr). Zurueckgesetzt.
* (c) high_connection_count: Schwellen-Vergleich in ``engine`` von ``<=`` auf ``<``
  verfaelscht (Off-by-one) -> ``test_rule_c_grenze_*`` ROT (Wert == Schwelle wuerde
  faelschlich treffen). Zurueckgesetzt.
* (b2) host_remote_access_port: in ``_eval_host_remote_port`` die Schnittmenge
  verfaelscht (``matched = host.open_ports`` statt ``host.open_ports & rule.ports``)
  -> ``test_rule_b2_nur_gewoehnliche_ports_trifft_nicht`` ROT (80/443 treffen
  faelschlich). Zurueckgesetzt.
* (b3) new_host_seen: in ``_eval_host_new`` die ``is_known``-Pruefung invertiert
  (``if not host.is_known or not host.ip:`` statt ``if host.is_known or not host.ip:``,
  sodass BEKANNTE Hosts treffen) -> ``test_rule_b3_bekannter_host_trifft_nicht`` ROT
  (der bekannte Host schlaegt faelschlich an). Zurueckgesetzt.
* (b2b) host_many_high_ports: in ``_eval_host_port_count`` den Schwellen-Vergleich von
  ``<=`` auf ``<`` verfaelscht (Off-by-one, ``>=`` statt ``>``) ->
  ``test_rule_b2b_genau_10_hohe_ports_trifft_nicht`` ROT (genau 10 Ports wuerden
  faelschlich treffen). Zurueckgesetzt.
* (b2b) host_many_high_ports: in ``_eval_host_port_count`` die ``port_floor``-Filterung
  entfernt (``high_ports = set(host.open_ports)`` statt nur ``port > rule.port_floor``)
  -> ``test_rule_b2b_nur_niedrige_ports_trifft_nicht`` ROT (11 niedrige Ports wuerden
  faelschlich treffen). Zurueckgesetzt.
* (b2c) host_backdoor_port: die severity der Regel in ``DEFAULT_RULES`` faelschlich von
  ``"critical"`` auf ``"notable"`` gesetzt -> ``test_rule_b2c_koexistenz_critical_vor_notable``
  ROT (die Backdoor-Observation sortiert dann nicht mehr garantiert VOR der
  Fernzugriffs-Observation -- gleiche severity, dann entscheidet die rule_id, und
  "host_backdoor_port" < "host_remote_access_port" bliebe nur zufaellig vorn; der Test
  prueft die severity beider explizit). Zurueckgesetzt.
"""

import pytest

from domain.analysis import (
    DEFAULT_RULES,
    ObservedConnection,
    ObservedHost,
    ObservedProcess,
    Rule,
    Snapshot,
    evaluate,
)

# ── Helfer ──────────────────────────────────────────────────────────────────


def _conn(
    *,
    pid: int | None = None,
    remote_ip: str | None = None,
    remote_port: int | None = None,
) -> ObservedConnection:
    return ObservedConnection(
        app_name="app",
        pid=pid,
        remote_ip=remote_ip,
        remote_port=remote_port,
        l4="tcp",
        status="ESTABLISHED",
    )


def _proc(
    pid: int,
    *,
    kind: str = "userland",
    exe_path: str | None = "/usr/bin/foo",
    cmdline: tuple[str, ...] = ("foo",),
) -> ObservedProcess:
    return ObservedProcess(pid=pid, name="foo", kind=kind, exe_path=exe_path, cmdline=cmdline)


def _host(
    ip: str,
    *,
    open_ports: frozenset[int] = frozenset(),
    is_known: bool = True,
) -> ObservedHost:
    return ObservedHost(
        ip=ip, hostname="host", vendor="ACME", open_ports=open_ports, is_known=is_known
    )


# ── leerer Snapshot ─────────────────────────────────────────────────────────


def test_leerer_snapshot_keine_beobachtungen() -> None:
    assert evaluate(Snapshot(), DEFAULT_RULES) == []


def test_keine_treffer_keine_beobachtungen() -> None:
    # Unauffaelliger Prozess, unauffaelliger Port, wenige Verbindungen -> nichts.
    snap = Snapshot(
        processes=(_proc(100, exe_path="/usr/bin/foo"),),
        connections=(_conn(pid=100, remote_ip="1.2.3.4", remote_port=443),),
    )
    assert evaluate(snap, DEFAULT_RULES) == []


# ── KERNFIX: echte Kernel-Threads sind raus ──────────────────────────────────


def test_kernel_thread_erzeugt_keine_beobachtung() -> None:
    """Ein kind=="kernel"-Prozess ohne exe_path und mit leerem cmdline -> KEINE Beobachtung.

    Der Kernfix: vorher (kombinierte Logik ohne kind-Pruefung) waere genau das ein
    Treffer gewesen -- echte Kernel-Threads (kswapd/kworker/...) haben nie einen exe_path,
    das ist ihre Natur, kein Verhalten.

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): den Waechter
    ``if proc.kind == "kernel": continue`` in ``_eval_process_masquerade`` entfernt
    -> dieser Test ROT (der Kernel-Thread schlaegt faelschlich als Tarnverdacht an).
    """
    snap = Snapshot(processes=(_proc(2, kind="kernel", exe_path=None, cmdline=()),))
    assert evaluate(snap, DEFAULT_RULES) == []


# ── (a) process_temp_path (Userland, exe_path unter temp-Praefix) ─────────────


def test_rule_a_tmp_pfad_trifft() -> None:
    """Userland-Prozess mit exe_path unter /tmp/ -> (a) notable.

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): das Pfad-Praefix
    ``/tmp/`` aus ``DEFAULT_RULES`` (process_temp_path) entfernt -> dieser Test ROT
    (der /tmp-Treffer entfaellt).
    """
    snap = Snapshot(processes=(_proc(7, exe_path="/tmp/evil"),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_temp_path"
    assert obs[0].help_kind == "process_suspicious_path"
    assert obs[0].kind == "process_temp_path"
    assert obs[0].severity == "notable"
    assert obs[0].subject == "pid 7"
    assert "/tmp/evil" in obs[0].detail


def test_rule_a_kernel_thread_in_temp_trifft_nicht() -> None:
    # Selbst ein kernel-Prozess mit /tmp-Pfad ist raus (kind-Filter vor dem Pfad-Check).
    snap = Snapshot(processes=(_proc(7, kind="kernel", exe_path="/tmp/evil"),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_a_normaler_pfad_trifft_nicht() -> None:
    snap = Snapshot(processes=(_proc(8, exe_path="/usr/bin/legit"),))
    assert evaluate(snap, DEFAULT_RULES) == []


# ── (a2) process_masquerade (Userland-Tarnverdacht) ───────────────────────────


@pytest.mark.parametrize("full_visibility", [False, True])
def test_rule_a2_leere_cmdline_trifft_info(full_visibility: bool) -> None:
    # Userland mit leerem cmdline (aber kind="userland") -> (a2)(i) info (Tarnverdacht).
    # In BEIDEN Modi verlaesslich: ein leeres cmdline trifft mit UND ohne volle Sicht.
    snap = Snapshot(
        processes=(_proc(50, exe_path="/usr/bin/foo", cmdline=()),),
        full_process_visibility=full_visibility,
    )
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_masquerade"
    assert obs[0].help_kind == "process_masquerade"
    assert obs[0].kind == "process_masquerade"
    assert obs[0].severity == "info"
    assert obs[0].subject == "pid 50"


def test_masquerade_kein_pfad_rootless_schweigt() -> None:
    """Userland ohne exe_path, OHNE volle Sicht (Default rootless) -> KEIN Treffer.

    Rootless ist ein fehlender Pfad mehrdeutig (evtl. nur fehlende Leserechte), kein
    verlaessliches Signal -- die Regel schweigt (Vision 4.4: kein Anschwaerzen von
    Harmlosem). cmdline ist gefuellt, also greift auch (i) nicht.

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): den
    ``full_process_visibility``-Waechter in (ii) entfernt (``if path is None:`` statt
    ``if path is None and snapshot.full_process_visibility:``) -> dieser Test ROT (der
    fehlende Pfad schlaegt auch rootless als Tarnverdacht an).
    """
    snap = Snapshot(processes=(_proc(123, exe_path=None),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_masquerade_kein_pfad_unter_root_notable() -> None:
    # Derselbe Prozess, aber unter voller Sicht (Root): kein Pfad trotz Lesrecht ist ein
    # echtes, staerkeres Signal -> genau EINE Beobachtung, severity notable.
    snap = Snapshot(processes=(_proc(123, exe_path=None),), full_process_visibility=True)
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_masquerade"
    assert obs[0].severity == "notable"
    assert obs[0].subject == "pid 123"


def test_masquerade_beide_ausloeser_unter_root_eine_notable() -> None:
    # Userland, exe_path None UND leeres cmdline, unter voller Sicht: genau EINE
    # Beobachtung, Prioritaet (ii) -> notable (nicht zwei, nicht info).
    snap = Snapshot(
        processes=(_proc(77, exe_path=None, cmdline=()),),
        full_process_visibility=True,
    )
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_masquerade"
    assert obs[0].severity == "notable"
    assert obs[0].subject == "pid 77"


def test_masquerade_beide_ausloeser_rootless_eine_info() -> None:
    # Derselbe Prozess rootless (Default): (ii) faellt weg, (i) leeres cmdline greift ->
    # genau EINE Beobachtung, severity info.
    snap = Snapshot(processes=(_proc(77, exe_path=None, cmdline=()),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_masquerade"
    assert obs[0].severity == "info"
    assert obs[0].subject == "pid 77"


def test_disjunkt_tmp_userland_erzeugt_genau_eine_beobachtung() -> None:
    # Ein /tmp-Userland-Prozess loest GENAU (a) aus, nicht zusaetzlich (a2) -- disjunkt.
    snap = Snapshot(processes=(_proc(9, exe_path="/tmp/evil"),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_temp_path"


# ── (b) remote_access_port ──────────────────────────────────────────────────


def test_rule_b_fernzugriffs_port_trifft() -> None:
    snap = Snapshot(connections=(_conn(remote_ip="1.2.3.4", remote_port=5900),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "remote_access_port"
    assert obs[0].help_kind == "remote_access_port"
    assert obs[0].kind == "connection_remote_port"
    assert obs[0].subject == "1.2.3.4:5900"


def test_rule_b_gewoehnlicher_port_trifft_nicht() -> None:
    snap = Snapshot(connections=(_conn(remote_ip="1.2.3.4", remote_port=443),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b_ohne_ip_nutzt_port_als_subject() -> None:
    snap = Snapshot(connections=(_conn(remote_ip=None, remote_port=22),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].subject == "port 22"


# ── (b2) host_remote_access_port (Geraet haelt Fernzugriffs-Port offen) ───────


def test_rule_b2_host_mit_offenem_port_22_trifft() -> None:
    """Host mit offenem Port 22 -> genau EINE Observation der host-Regel.

    Geraeteseitiges Gegenstueck zu (b): nicht eine Verbindung ZU Port 22, sondern ein
    Geraet, das Port 22 OFFEN haelt. subject ist die Host-ip, der Port steht im detail.
    """
    snap = Snapshot(hosts=(_host("10.0.0.5", open_ports=frozenset({22})),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "host_remote_access_port"
    assert obs[0].help_kind == "remote_access_port"
    assert obs[0].kind == "host_remote_port"
    assert obs[0].severity == "notable"
    assert obs[0].subject == "10.0.0.5"
    assert "22" in obs[0].detail


def test_rule_b2_mehrere_fernzugriffs_ports_eine_gebuendelte_observation() -> None:
    """Host mit 22 UND 3389 offen -> genau EINE Observation, beide Ports gebuendelt.

    Die Buendelung verhindert Mehrfach-Meldung desselben Geraets: pro Host eine
    Beobachtung, die getroffenen Ports aufsteigend sortiert im value ("22, 3389").
    """
    snap = Snapshot(hosts=(_host("10.0.0.6", open_ports=frozenset({3389, 22})),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "host_remote_access_port"
    assert obs[0].subject == "10.0.0.6"
    assert "22, 3389" in obs[0].detail


def test_rule_b2_nur_gewoehnliche_ports_trifft_nicht() -> None:
    """Host mit nur 80/443 offen -> KEINE host-Observation (kein Fernzugriffs-Port).

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): in
    ``_eval_host_remote_port`` die Schnittmengen-Pruefung verfaelscht
    (``matched = host.open_ports`` statt ``host.open_ports & rule.ports``, also ALLE
    offenen Ports als Treffer) -> dieser Test ROT (80/443 wuerden faelschlich treffen).
    Zurueckgesetzt.
    """
    snap = Snapshot(hosts=(_host("10.0.0.7", open_ports=frozenset({80, 443})),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b2_host_ohne_offene_ports_trifft_nicht() -> None:
    snap = Snapshot(hosts=(_host("10.0.0.8", open_ports=frozenset()),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b2_zwei_hosts_je_port_22_nach_subject_sortiert() -> None:
    # Zwei Hosts mit je offenem 22 -> zwei Observations, nach subject (ip) sortiert.
    snap = Snapshot(
        hosts=(
            _host("10.0.0.20", open_ports=frozenset({22})),
            _host("10.0.0.10", open_ports=frozenset({22})),
        )
    )
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "host_remote_access_port"]
    assert len(obs) == 2
    assert [o.subject for o in obs] == ["10.0.0.10", "10.0.0.20"]


def test_rule_b2_host_ohne_ip_wird_uebersprungen() -> None:
    # Leere ip -> kein sinnvolles subject -> uebersprungen, trotz offenem Fernzugriffs-Port.
    snap = Snapshot(hosts=(_host("", open_ports=frozenset({22})),))
    assert evaluate(snap, DEFAULT_RULES) == []


# ── (b2b) host_many_high_ports (Host haelt viele hohe Ports offen) ────────────


def test_rule_b2b_genau_10_hohe_ports_trifft_nicht() -> None:
    """Host mit genau 10 hohen Ports (>1024) -> KEIN Treffer (strikt groesser, 10 ist nicht >10).

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): in
    ``_eval_host_port_count`` den Schwellen-Vergleich von ``<=`` auf ``<`` verfaelscht
    (Off-by-one, ``>=`` statt ``>``) -> dieser Test ROT (genau 10 Ports wuerden
    faelschlich treffen). Zurueckgesetzt.
    """
    ports = frozenset(range(2000, 2010))  # 10 hohe Ports
    snap = Snapshot(hosts=(_host("10.0.1.5", open_ports=ports),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b2b_elf_hohe_ports_trifft() -> None:
    """Host mit 11 hohen Ports (>1024) -> genau EINE Observation, value == "11"."""
    ports = frozenset(range(2000, 2011))  # 11 hohe Ports
    snap = Snapshot(hosts=(_host("10.0.1.6", open_ports=ports),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "host_many_high_ports"
    assert obs[0].help_kind == "many_high_ports"
    assert obs[0].kind == "host_port_count"
    assert obs[0].severity == "notable"
    assert obs[0].subject == "10.0.1.6"
    assert (
        obs[0].detail == "Host 10.0.1.6 haelt 11 Ports oberhalb 1024 offen -- ungewoehnlich viele."
    )


def test_rule_b2b_nur_niedrige_ports_trifft_nicht() -> None:
    """Host mit 11 NIEDRIGEN Ports (<=1024) -> KEIN Treffer (port_floor greift).

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): in
    ``_eval_host_port_count`` die ``port_floor``-Filterung entfernt
    (``high_ports = set(host.open_ports)``) -> dieser Test ROT (11 niedrige Ports wuerden
    faelschlich treffen). Zurueckgesetzt.
    """
    ports = frozenset(range(1010, 1021))  # 11 Ports, alle <= 1024
    snap = Snapshot(hosts=(_host("10.0.1.7", open_ports=ports),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b2b_mischung_zaehlt_nur_hohe_ports() -> None:
    """Host mit 5 niedrigen + 11 hohen Ports -> Treffer, value == "11" (nur hohe zaehlen)."""
    ports = frozenset(range(100, 105)) | frozenset(range(2000, 2011))  # 5 niedrig + 11 hoch
    snap = Snapshot(hosts=(_host("10.0.1.8", open_ports=ports),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "host_many_high_ports"
    assert obs[0].subject == "10.0.1.8"
    assert "11" in obs[0].detail


def test_rule_b2b_host_ohne_ip_wird_uebersprungen() -> None:
    # Leere ip -> kein sinnvolles subject -> uebersprungen, trotz vieler hoher Ports.
    snap = Snapshot(hosts=(_host("", open_ports=frozenset(range(2000, 2011))),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b2b_ein_host_genau_eine_beobachtung() -> None:
    # Buendelung/Determinismus: ein Host mit vielen hohen Ports -> genau EINE Beobachtung.
    snap = Snapshot(hosts=(_host("10.0.1.9", open_ports=frozenset(range(2000, 2020))),))
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "host_many_high_ports"]
    assert len(obs) == 1
    assert obs[0].subject == "10.0.1.9"


# ── (b2c) host_backdoor_port (Host haelt einen Backdoor-Port offen, critical) ─


def test_rule_b2c_einzelner_backdoor_port_trifft_critical() -> None:
    """Host mit genau einem Backdoor-Port (31337) -> genau EINE critical-Observation.

    Erster echter ``critical``-Setzer (ADR 0022): nutzt den bestehenden
    ``kind="host_remote_port"`` mit eigener Portmenge und eigenem ``help_kind``.
    """
    snap = Snapshot(hosts=(_host("10.0.2.5", open_ports=frozenset({31337})),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "host_backdoor_port"
    assert obs[0].help_kind == "backdoor_port"
    assert obs[0].kind == "host_remote_port"
    assert obs[0].severity == "critical"
    assert obs[0].subject == "10.0.2.5"
    assert "31337" in obs[0].detail


def test_rule_b2c_mehrere_backdoor_ports_eine_gebuendelte_observation() -> None:
    """Host mit 31337 UND 12345 offen -> genau EINE Observation, beide Ports aufsteigend.

    Buendelung pro Host (eine rote Markierung je Geraet): die getroffenen Ports
    aufsteigend sortiert, kommagetrennt im value ("12345, 31337").
    """
    snap = Snapshot(hosts=(_host("10.0.2.6", open_ports=frozenset({31337, 12345})),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "host_backdoor_port"
    assert obs[0].subject == "10.0.2.6"
    assert "12345, 31337" in obs[0].detail


def test_rule_b2c_kein_backdoor_port_trifft_nicht() -> None:
    # Host mit nur gewoehnlichen Ports (80, 443) -> kein Backdoor-Treffer.
    snap = Snapshot(hosts=(_host("10.0.2.7", open_ports=frozenset({80, 443})),))
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "host_backdoor_port"]
    assert obs == []


def test_rule_b2c_host_ohne_ip_wird_uebersprungen() -> None:
    # Leere ip -> kein sinnvolles subject -> uebersprungen, trotz offenem Backdoor-Port.
    snap = Snapshot(hosts=(_host("", open_ports=frozenset({31337})),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b2c_koexistenz_critical_vor_notable() -> None:
    """Zwei-Achsen: Host mit 22 (Fernzugriff, notable) UND 31337 (Backdoor, critical).

    Beide host_remote_port-Regeln koexistieren auf demselben Geraet -> ZWEI unabhaengige
    Observations. Die globale Sortierung (_SEVERITY_RANK) stellt die critical-Backdoor-
    Observation VOR die notable-Fernzugriffs-Observation.

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): severity der Regel
    ``host_backdoor_port`` in ``DEFAULT_RULES`` von ``"critical"`` auf ``"notable"``
    verfaelscht -> dieser Test ROT (beide severities waeren dann "notable"). Zurueckgesetzt.
    """
    snap = Snapshot(hosts=(_host("10.0.2.8", open_ports=frozenset({22, 31337})),))
    obs = [
        o
        for o in evaluate(snap, DEFAULT_RULES)
        if o.rule_id in {"host_backdoor_port", "host_remote_access_port"}
    ]
    assert len(obs) == 2
    assert obs[0].rule_id == "host_backdoor_port"
    assert obs[0].severity == "critical"
    assert obs[1].rule_id == "host_remote_access_port"
    assert obs[1].severity == "notable"


# ── (b3) new_host_seen (Geraet taucht erstmals im Netz auf) ───────────────────


def test_rule_b3_neuer_host_trifft() -> None:
    """ObservedHost mit is_known=False und gesetzter ip -> genau EINE Observation.

    analysis' erstes GEDAECHTNIS: ``is_known`` ist ein Snapshot-FAKTUM (von der
    Projektion in C.2 gefuellt); die Engine wertet nur das bool aus. subject ist die ip.
    """
    snap = Snapshot(hosts=(_host("10.0.0.99", is_known=False),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "new_host_seen"
    assert obs[0].help_kind == "new_host"
    assert obs[0].kind == "host_new"
    assert obs[0].severity == "notable"
    assert obs[0].subject == "10.0.0.99"


def test_rule_b3_bekannter_host_trifft_nicht() -> None:
    """ObservedHost mit is_known=True -> KEINE Observation (bekannter Host, Default-Fall).

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): in ``_eval_host_new``
    die ``is_known``-Pruefung invertiert (``if not host.is_known or not host.ip:`` statt
    ``if host.is_known or not host.ip:``, sodass BEKANNTE Hosts treffen) -> dieser Test
    ROT (der bekannte Host schlaegt faelschlich an). Zurueckgesetzt.
    """
    snap = Snapshot(hosts=(_host("10.0.0.99", is_known=True),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b3_neuer_host_ohne_ip_trifft_nicht() -> None:
    # is_known=False, aber leere ip -> kein sinnvolles subject -> uebersprungen.
    snap = Snapshot(hosts=(_host("", is_known=False),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b3_default_is_known_true_schlaegt_nicht_an() -> None:
    """Ein ObservedHost OHNE explizites is_known schlaegt NICHT an -- zurueckhaltender Default.

    Sichert, dass der Default ``is_known=True`` ist ("im Zweifel bekannt"): ein
    unbekannter Historie-Zustand soll nicht faelschlich als neuer Host anschlagen.
    """
    host = ObservedHost(ip="10.0.0.42")  # is_known nicht gesetzt
    assert host.is_known is True
    assert evaluate(Snapshot(hosts=(host,)), DEFAULT_RULES) == []


# ── (c) high_connection_count ───────────────────────────────────────────────


def test_rule_c_ueber_schwelle_trifft() -> None:
    # 51 Verbindungen desselben pid -> ueber der Default-Schwelle 50.
    conns = tuple(_conn(pid=42, remote_ip="9.9.9.9", remote_port=443) for _ in range(51))
    snap = Snapshot(connections=conns)
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "high_connection_count"]
    assert len(obs) == 1
    assert obs[0].kind == "pid_connection_count"
    assert obs[0].subject == "pid 42"
    assert "51" in obs[0].detail


def test_rule_c_grenze_genau_schwelle_trifft_nicht() -> None:
    # Genau 50 == Schwelle -> KEIN Treffer (strikt groesser). Faengt Off-by-one.
    conns = tuple(_conn(pid=42, remote_ip="9.9.9.9", remote_port=443) for _ in range(50))
    snap = Snapshot(connections=conns)
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "high_connection_count"]
    assert obs == []


def test_rule_c_verbindungen_ohne_pid_zaehlen_nicht() -> None:
    # 60 Verbindungen ohne pid -> keiner Zaehlung zuordenbar -> kein Treffer.
    conns = tuple(_conn(pid=None, remote_ip="9.9.9.9", remote_port=443) for _ in range(60))
    snap = Snapshot(connections=conns)
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "high_connection_count"]
    assert obs == []


# ── Determinismus + Sortierung ──────────────────────────────────────────────


def test_evaluate_deterministisch() -> None:
    snap = Snapshot(
        processes=(_proc(5, exe_path="/tmp/x"),),
        connections=(_conn(remote_ip="1.2.3.4", remote_port=22),),
    )
    assert evaluate(snap, DEFAULT_RULES) == evaluate(snap, DEFAULT_RULES)


def test_sortierung_notable_vor_info_dann_rule_id_dann_subject() -> None:
    # Mischung mehrerer Regeln: zwei "notable" (process_temp_path, remote_access_port)
    # und eine "info" (high_connection_count). Der /tmp-Prozess ist userland (Default).
    many_conns = tuple(_conn(pid=42, remote_ip="9.9.9.9", remote_port=443) for _ in range(51))
    snap = Snapshot(
        processes=(_proc(20, exe_path="/tmp/a"),),
        connections=(_conn(remote_ip="8.8.8.8", remote_port=3389), *many_conns),
    )
    obs = evaluate(snap, DEFAULT_RULES)
    rule_ids = [o.rule_id for o in obs]
    # notable (process_temp_path, remote_access_port) vor info (high_connection_count);
    # innerhalb notable nach rule_id: process_temp_path < remote_access_port.
    assert rule_ids == [
        "process_temp_path",
        "remote_access_port",
        "high_connection_count",
    ]
    severities = [o.severity for o in obs]
    assert severities == ["notable", "notable", "info"]


def test_sortierung_critical_vor_notable_vor_info() -> None:
    # Severity-Rang: critical sortiert VOR notable VOR info. critical kommt aktuell aus
    # keiner Built-in-Regel (additiv eingefuehrt, ADR 0022) -- darum wird hier eine
    # ad-hoc Regel mit severity="critical" auf einem eigenen Port (4444, NICHT in den
    # Default-Fernzugriffs-Ports) zu DEFAULT_RULES gestellt. Daneben eine Default-notable
    # (remote_access_port auf 5900) und eine Default-info (high_connection_count).
    many_conns = tuple(_conn(pid=42, remote_ip="9.9.9.9", remote_port=80) for _ in range(51))
    snap = Snapshot(
        connections=(
            _conn(remote_ip="6.6.6.6", remote_port=4444),
            _conn(remote_ip="7.7.7.7", remote_port=5900),
            *many_conns,
        ),
    )
    critical_rule = Rule(
        id="critical_test_port",
        severity="critical",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Kritischer Port",
        detail_template="Verbindung zu {subject} nutzt einen kritischen Port ({value}).",
        ports=frozenset({4444}),
    )
    obs = evaluate(snap, (*DEFAULT_RULES, critical_rule))
    severities = [o.severity for o in obs]
    # critical zuerst, dann notable, dann info -- die starke Stufe gewinnt die Ordnung.
    assert severities == ["critical", "notable", "info"]
    assert obs[0].rule_id == "critical_test_port"
    assert obs[0].subject == "6.6.6.6:4444"


def test_sortierung_subject_innerhalb_gleicher_rule() -> None:
    # Zwei Treffer derselben Regel -> nach subject aufsteigend.
    snap = Snapshot(
        connections=(
            _conn(remote_ip="2.2.2.2", remote_port=22),
            _conn(remote_ip="1.1.1.1", remote_port=22),
        )
    )
    obs = evaluate(snap, DEFAULT_RULES)
    subjects = [o.subject for o in obs]
    assert subjects == ["1.1.1.1:22", "2.2.2.2:22"]
