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
* (a) process_temp_path: Pfad-Praefix ``/tmp/`` aus ``DEFAULT_RULES`` entfernt
  -> ``test_rule_a_tmp_pfad_trifft`` ROT (der /tmp-Treffer entfaellt). Zurueckgesetzt.
* (b) remote_access_port: Portmenge in ``DEFAULT_RULES`` geleert (``frozenset()``)
  -> ``test_rule_b_*`` ROT (kein Port trifft mehr). Zurueckgesetzt.
* (c) high_connection_count: Schwellen-Vergleich in ``engine`` von ``<=`` auf ``<``
  verfaelscht (Off-by-one) -> ``test_rule_c_grenze_*`` ROT (Wert == Schwelle wuerde
  faelschlich treffen). Zurueckgesetzt.
"""

from domain.analysis import (
    DEFAULT_RULES,
    ObservedConnection,
    ObservedProcess,
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


def test_rule_a2_leere_cmdline_trifft_info() -> None:
    # Userland mit leerem cmdline (aber kind="userland") -> (a2) info (Tarnverdacht).
    snap = Snapshot(processes=(_proc(50, exe_path="/usr/bin/foo", cmdline=()),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_masquerade"
    assert obs[0].help_kind == "process_masquerade"
    assert obs[0].severity == "info"
    assert obs[0].subject == "pid 50"


def test_rule_a2_kein_exe_path_trifft_info() -> None:
    # Userland mit exe_path None (kind="userland") -> (a2) info.
    snap = Snapshot(processes=(_proc(123, exe_path=None),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].rule_id == "process_masquerade"
    assert obs[0].severity == "info"
    assert obs[0].subject == "pid 123"


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
    assert obs[0].subject == "1.2.3.4:5900"


def test_rule_b_gewoehnlicher_port_trifft_nicht() -> None:
    snap = Snapshot(connections=(_conn(remote_ip="1.2.3.4", remote_port=443),))
    assert evaluate(snap, DEFAULT_RULES) == []


def test_rule_b_ohne_ip_nutzt_port_als_subject() -> None:
    snap = Snapshot(connections=(_conn(remote_ip=None, remote_port=22),))
    obs = evaluate(snap, DEFAULT_RULES)
    assert len(obs) == 1
    assert obs[0].subject == "port 22"


# ── (c) high_connection_count ───────────────────────────────────────────────


def test_rule_c_ueber_schwelle_trifft() -> None:
    # 51 Verbindungen desselben pid -> ueber der Default-Schwelle 50.
    conns = tuple(_conn(pid=42, remote_ip="9.9.9.9", remote_port=443) for _ in range(51))
    snap = Snapshot(connections=conns)
    obs = [o for o in evaluate(snap, DEFAULT_RULES) if o.rule_id == "high_connection_count"]
    assert len(obs) == 1
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
