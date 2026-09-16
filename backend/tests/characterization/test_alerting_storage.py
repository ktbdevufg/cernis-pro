"""Characterization-Contract der alerting-DB-Round-trips (Altcode modules/alerting.py).

Gegen eine temporaere DB (Muster wie test_monitoring_storage / test_scan_history_storage):
``DB_PATH`` wird AM MODUL-NAMESPACE umgebogen (``monkeypatch.setattr(alerting, "DB_PATH",
...)``), NICHT via Env -- ``modules.db_path.DB_PATH`` ist beim Import bereits als String
gebunden (``from modules.db_path import DB_PATH``), ein spaetes Setzen der Env-Var
aenderte diesen Wert nicht mehr.

Festgehalten wird der Ist-Zustand VOR der A.2+-Migration (Strangler-Fig):
    CRUD:       add_rule/update_rule/delete_rule -> get_rules
    history:    get_alert_history (leere DB + manuelle Inserts)
    dispatcher: fire_alert (toter Pfad, direkt aufgerufen -- s.u.)

Eingefrorene Wire-Vertraege (AS-IS, duerfen in A.2+ NICHT still kippen):
  * ``enabled`` / ``notify_email`` / ``notify_macos`` sind INTEGER 0/1, NIE bool --
    das Frontend schickt int, SQLite speichert int, ``get_rules`` gibt int zurueck.
  * ``get_rules`` liefert ``last_triggered`` mit (AS-IS). Das Weglassen aus der
    REST-Response ist eine A.6-Entscheidung (REST-View), nicht hier; in Storage +
    fire_alert bleibt ``last_triggered`` (Cooldown braucht es).

EINE bewusste v2-HEILUNG (NICHT der Altcode-Ist-Zustand):
  * ``get_alert_history`` gegen leere DB NACH ``init_alerts_db`` -> ``[]``. Der Altcode
    rief in ``get_alert_history`` KEIN ``init_alerts_db`` (alerting.py:118) -> gegen eine
    DB ohne Tabelle warf er ``sqlite3.OperationalError`` (am nackten Endpunkt -> HTTP 500,
    da main.py keinen exception_handler hat). v2 heilt das: ein Lese-Use-Case laeuft gegen
    eine initialisierte DB und liefert ``[]``. Dieser Test friert bewusst den GESUNDEN
    Zustand ein, nicht den kaputten 500.

``fire_alert`` ist im gesamten Repo nirgends aufgerufen (toter Schreibpfad -- ``main.py``
importiert es nur). Es wird hier dennoch AS-IS charakterisiert (analog M.1, das den
kaputten metrics-alive-Block einfror): DIREKT aufgerufen, ``notify_macos``/``notify_email``
am alerting-Namespace gemockt -- nicht ueber den nie-getriggerten monitor-Pfad.
"""

from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def alerting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    from modules import alerting as alerting_mod

    monkeypatch.setattr(alerting_mod, "DB_PATH", str(tmp_path / "cernis.db"))
    return alerting_mod


# ── init ──────────────────────────────────────────────────────


def test_init_alerts_db_idempotent(alerting: Any) -> None:
    # 2x rufen -> kein Fehler; beide Tabellen vorhanden.
    alerting.init_alerts_db()
    alerting.init_alerts_db()

    import sqlite3

    conn = sqlite3.connect(alerting.DB_PATH)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"alert_rules", "alert_history"} <= names


# ── add_rule / get_rules ──────────────────────────────────────


def test_add_rule_returns_int_rowid(alerting: Any) -> None:
    rule_id = alerting.add_rule("My Rule", "host_down")
    assert isinstance(rule_id, int)
    assert rule_id >= 1


def test_add_rule_defaults_are_as_is(alerting: Any) -> None:
    # Defaults wie modules/alerting.py: target='any', threshold=60,
    # notify_email=0, notify_macos=1, enabled=1, last_triggered=0.0.
    alerting.add_rule("R", "host_down")
    rows = alerting.get_rules()
    assert len(rows) == 1
    row = rows[0]
    assert row["target"] == "any"
    assert row["threshold"] == 60
    assert row["notify_email"] == 0
    assert row["notify_macos"] == 1
    assert row["enabled"] == 1
    assert row["last_triggered"] == 0.0


def test_get_rules_enabled_flags_are_int_not_bool(alerting: Any) -> None:
    # WIRE-VERTRAG: enabled/notify_* sind int 0/1, NICHT bool. Darf in A.2+
    # nicht still nach bool kippen (z.B. durch ein pydantic-Response-Modell).
    alerting.add_rule("R", "host_down", notify_email=False, notify_macos=True)
    row = alerting.get_rules()[0]
    for key in ("enabled", "notify_email", "notify_macos"):
        assert type(row[key]) is int, f"{key} muss int sein, ist {type(row[key]).__name__}"
    assert row["notify_email"] == 0
    assert row["notify_macos"] == 1


def test_get_rules_contains_last_triggered_as_is(alerting: Any) -> None:
    # AS-IS: get_rules liefert last_triggered mit. Weglassen ist A.6-Sache.
    alerting.add_rule("R", "host_down")
    row = alerting.get_rules()[0]
    assert "last_triggered" in row
    assert row["last_triggered"] == 0.0


def test_get_rules_full_column_set(alerting: Any) -> None:
    alerting.add_rule("R", "host_down")
    row = alerting.get_rules()[0]
    assert set(row.keys()) == {
        "id",
        "name",
        "rule_type",
        "target",
        "threshold",
        "notify_email",
        "notify_macos",
        "enabled",
        "last_triggered",
    }


def test_get_rules_ordered_by_id(alerting: Any) -> None:
    alerting.add_rule("A", "host_down")
    alerting.add_rule("B", "new_device")
    alerting.add_rule("C", "cert_expiry")
    rows = alerting.get_rules()
    assert [r["name"] for r in rows] == ["A", "B", "C"]
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)


def test_get_rules_empty_when_none_added(alerting: Any) -> None:
    # get_rules ruft init_alerts_db selbst -> robust gegen leere DB.
    assert alerting.get_rules() == []


# ── update_rule ───────────────────────────────────────────────


def test_update_rule_whitelist_applies_allowed_keys(alerting: Any) -> None:
    rule_id = alerting.add_rule("R", "host_down")
    alerting.update_rule(
        rule_id,
        name="Renamed",
        threshold=120,
        target="10.0.0.1",
        notify_email=1,
        notify_macos=0,
    )
    row = alerting.get_rules()[0]
    assert row["name"] == "Renamed"
    assert row["threshold"] == 120
    assert row["target"] == "10.0.0.1"
    assert row["notify_email"] == 1
    assert row["notify_macos"] == 0


def test_update_rule_enabled_int_stored_raw(alerting: Any) -> None:
    # Frontend-Toggle schickt enabled als int 0/1 (AlertsView), roh gespeichert.
    rule_id = alerting.add_rule("R", "host_down")
    alerting.update_rule(rule_id, enabled=0)
    assert alerting.get_rules()[0]["enabled"] == 0
    alerting.update_rule(rule_id, enabled=1)
    assert alerting.get_rules()[0]["enabled"] == 1


def test_update_rule_ignores_non_whitelisted_keys(alerting: Any) -> None:
    # AS-IS: nur {name,enabled,threshold,notify_email,notify_macos,target} erlaubt.
    # rule_type/id/last_triggered sind NICHT in der Whitelist -> ignoriert.
    rule_id = alerting.add_rule("R", "host_down")
    alerting.update_rule(rule_id, rule_type="new_device", last_triggered=999.0)
    row = alerting.get_rules()[0]
    assert row["rule_type"] == "host_down"
    assert row["last_triggered"] == 0.0


def test_update_rule_empty_kwargs_is_noop(alerting: Any) -> None:
    # Keine erlaubten keys -> kein UPDATE (parts leer), kein Fehler.
    rule_id = alerting.add_rule("R", "host_down")
    alerting.update_rule(rule_id)
    assert alerting.get_rules()[0]["name"] == "R"


# ── delete_rule ───────────────────────────────────────────────


def test_delete_rule_removes_row(alerting: Any) -> None:
    rule_id = alerting.add_rule("R", "host_down")
    alerting.delete_rule(rule_id)
    assert alerting.get_rules() == []


# ── get_alert_history ─────────────────────────────────────────


def test_get_alert_history_empty_after_init_returns_list(alerting: Any) -> None:
    # v2-HEILUNG (NICHT der Altcode-Ist-Zustand): leere DB NACH init -> [].
    # Altcode warf hier OperationalError (get_alert_history rief init nicht;
    # alerting.py:118), was am nackten Endpunkt zu HTTP 500 wurde. v2 liest gegen
    # eine initialisierte DB -> []. Dieser Test friert den GESUNDEN Zustand ein.
    alerting.init_alerts_db()
    assert alerting.get_alert_history() == []


def test_get_alert_history_newest_first_and_limit(alerting: Any) -> None:
    import sqlite3

    alerting.init_alerts_db()
    conn = sqlite3.connect(alerting.DB_PATH)
    for ts in (100.0, 300.0, 200.0):
        conn.execute(
            "INSERT INTO alert_history "
            "(rule_id, rule_name, rule_type, target, message, ts, datetime) "
            "VALUES (?,?,?,?,?,?,?)",
            (1, "R", "host_down", "any", f"msg-{ts}", ts, "2026-06-03 00:00:00"),
        )
    conn.commit()
    conn.close()

    rows = alerting.get_alert_history()
    # ORDER BY ts DESC
    assert [r["ts"] for r in rows] == [300.0, 200.0, 100.0]
    # limit greift
    assert len(alerting.get_alert_history(limit=1)) == 1


def test_get_alert_history_row_shape(alerting: Any) -> None:
    import sqlite3

    alerting.init_alerts_db()
    conn = sqlite3.connect(alerting.DB_PATH)
    conn.execute(
        "INSERT INTO alert_history "
        "(rule_id, rule_name, rule_type, target, message, ts, datetime) "
        "VALUES (?,?,?,?,?,?,?)",
        (1, "R", "host_down", "192.168.1.1", "host down", 1_700_000_000.0, "2026-06-03 00:00:00"),
    )
    conn.commit()
    conn.close()

    row = alerting.get_alert_history()[0]
    assert set(row.keys()) == {
        "id",
        "rule_id",
        "rule_name",
        "rule_type",
        "target",
        "message",
        "ts",
        "datetime",
    }


# ── fire_alert (toter Pfad, AS-IS direkt charakterisiert) ──────


@pytest.fixture
def fire_calls(alerting: Any, monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Faengt notify_macos/notify_email am alerting-Namespace ab (kein osascript/SMTP)."""
    calls: dict[str, list[Any]] = {"macos": [], "email": []}

    def fake_macos(*a: Any, **k: Any) -> None:
        calls["macos"].append((a, k))

    def fake_email(*a: Any, **k: Any) -> bool:
        calls["email"].append((a, k))
        return True

    monkeypatch.setattr(alerting, "notify_macos", fake_macos)
    monkeypatch.setattr(alerting, "notify_email", fake_email)
    alerting.init_alerts_db()
    return calls


def test_fire_alert_fires_on_first_match(alerting: Any, fire_calls: dict[str, list[Any]]) -> None:
    # last_triggered=0.0 beim Anlegen -> erster Match feuert immer.
    alerting.add_rule("R", "host_down", target="any", notify_macos=True)
    alerting.fire_alert("host_down", "192.168.1.1", "down")

    assert len(fire_calls["macos"]) == 1
    # History +1 Zeile geschrieben.
    assert len(alerting.get_alert_history()) == 1
    # last_triggered auf ~now gesetzt (war 0.0).
    assert alerting.get_rules()[0]["last_triggered"] > 0.0


# Stufe (a) — enabled: Gegenprobe-Paar. Dieselbe Regel feuert enabled, nicht disabled.
def test_fire_alert_enabled_rule_fires(alerting: Any, fire_calls: dict[str, list[Any]]) -> None:
    # Gegenprobe zu test_fire_alert_disabled_rule_does_not_fire: alle Bedingungen
    # erfuellt, enabled=1 -> feuert.
    alerting.add_rule("R", "host_down", target="any", notify_macos=True)  # enabled=1 default
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 1


def test_fire_alert_disabled_rule_does_not_fire(
    alerting: Any, fire_calls: dict[str, list[Any]]
) -> None:
    # Identisch zur Gegenprobe, NUR enabled=0 -> feuert nicht.
    rule_id = alerting.add_rule("R", "host_down", target="any", notify_macos=True)
    alerting.update_rule(rule_id, enabled=0)
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert fire_calls["macos"] == []
    assert alerting.get_alert_history() == []


# Stufe (b) — rule_type: Gegenprobe-Paar. Exakter type feuert, mismatch nicht.
def test_fire_alert_matching_rule_type_fires(
    alerting: Any, fire_calls: dict[str, list[Any]]
) -> None:
    # Gegenprobe: rule_type der Regel == gefeuerter rule_type -> feuert.
    alerting.add_rule("R", "host_down", target="any", notify_macos=True)
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 1


def test_fire_alert_rule_type_mismatch_does_not_fire(
    alerting: Any, fire_calls: dict[str, list[Any]]
) -> None:
    # Identisch zur Gegenprobe, NUR der gefeuerte rule_type weicht ab -> feuert nicht.
    alerting.add_rule("R", "host_down", target="any", notify_macos=True)
    alerting.fire_alert("new_device", "192.168.1.1", "new")
    assert fire_calls["macos"] == []


# Stufe (c) — target: beide Richtungen.
def test_fire_alert_target_any_matches_everything(
    alerting: Any, fire_calls: dict[str, list[Any]]
) -> None:
    alerting.add_rule("R", "host_down", target="any", notify_macos=True)
    alerting.fire_alert("host_down", "10.99.99.99", "down")
    assert len(fire_calls["macos"]) == 1


def test_fire_alert_specific_target_must_match_exactly(
    alerting: Any, fire_calls: dict[str, list[Any]]
) -> None:
    alerting.add_rule("R", "host_down", target="192.168.1.1", notify_macos=True)
    alerting.fire_alert("host_down", "192.168.1.2", "down")  # falsches Ziel -> nicht
    assert fire_calls["macos"] == []
    alerting.fire_alert("host_down", "192.168.1.1", "down")  # exaktes Ziel -> feuert
    assert len(fire_calls["macos"]) == 1


# Stufe (d) — Cooldown: innerhalb -> nicht; nach Ablauf -> wieder; Floor 60s.
# Zeit wird kontrolliert (alerting.time.time gemockt), um ohne echten sleep zu testen.
def test_fire_alert_cooldown_within_window_blocks_second(
    alerting: Any, fire_calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # threshold=120 -> Cooldown 120s. Bei t0 feuern, bei t0+60 (<120) NICHT erneut.
    clock = {"now": 1000.0}
    monkeypatch.setattr(alerting.time, "time", lambda: clock["now"])
    alerting.add_rule("R", "host_down", target="any", threshold=120, notify_macos=True)

    alerting.fire_alert("host_down", "192.168.1.1", "down")  # t0 -> feuert
    assert len(fire_calls["macos"]) == 1
    clock["now"] = 1060.0  # +60s, noch innerhalb 120s
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 1  # kein 2. Feuern


def test_fire_alert_cooldown_after_window_fires_again(
    alerting: Any, fire_calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # NACH Ablauf des Cooldowns feuert dieselbe Regel wieder (Gegenprobe zu "innerhalb").
    clock = {"now": 1000.0}
    monkeypatch.setattr(alerting.time, "time", lambda: clock["now"])
    alerting.add_rule("R", "host_down", target="any", threshold=120, notify_macos=True)

    alerting.fire_alert("host_down", "192.168.1.1", "down")  # t0 -> feuert
    assert len(fire_calls["macos"]) == 1
    clock["now"] = 1121.0  # +121s, nach 120s Cooldown
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 2  # feuert wieder
    assert len(alerting.get_alert_history()) == 2


def test_fire_alert_cooldown_floor_overrides_low_threshold(
    alerting: Any, fire_calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # KERN-PROBE des Floors: threshold=10, aber 30s seit last_triggered -> NICHT feuern,
    # obwohl 30>10. Beweist max(threshold,60)=60 statt threshold. Bei <60 wuerde die
    # Regel hier faelschlich feuern.
    clock = {"now": 1000.0}
    monkeypatch.setattr(alerting.time, "time", lambda: clock["now"])
    alerting.add_rule("R", "host_down", target="any", threshold=10, notify_macos=True)

    alerting.fire_alert("host_down", "192.168.1.1", "down")  # t0 -> feuert
    assert len(fire_calls["macos"]) == 1
    clock["now"] = 1030.0  # +30s: > threshold(10), aber < Floor(60)
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 1  # Floor blockt -> kein 2. Feuern
    clock["now"] = 1061.0  # +61s: jetzt > Floor(60)
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 2  # feuert wieder


def test_fire_alert_cooldown_boundary_is_strict_less_than(
    alerting: Any, fire_calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Grenzvertrag: der Altcode vergleicht `now - last_triggered < cooldown` (STRIKT <).
    # Bei GENAU cooldown Sekunden Abstand ist 60 < 60 falsch -> NICHT geblockt -> feuert.
    # Fixiert die <-vs-<=-Grenze (sonst kippt der Vertrag bei exakter Cooldown-Dauer).
    clock = {"now": 1000.0}
    monkeypatch.setattr(alerting.time, "time", lambda: clock["now"])
    alerting.add_rule("R", "host_down", target="any", threshold=120, notify_macos=True)

    alerting.fire_alert("host_down", "192.168.1.1", "down")  # t0 -> feuert
    assert len(fire_calls["macos"]) == 1
    clock["now"] = 1120.0  # +120s == cooldown exakt: 120 < 120 ist False -> feuert
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert len(fire_calls["macos"]) == 2


def test_fire_alert_email_only_with_flag_and_config(
    alerting: Any, fire_calls: dict[str, list[Any]]
) -> None:
    # notify_email nur, wenn rule.notify_email=1 UND smtp_config gesetzt.
    alerting.add_rule("R", "host_down", notify_email=True, notify_macos=False)

    # Kein smtp_config -> kein email.
    alerting.fire_alert("host_down", "192.168.1.1", "down")
    assert fire_calls["email"] == []

    # Cooldown abwarten umgehen: neue Regel mit smtp_config.
    alerting.add_rule("R2", "new_device", notify_email=True, notify_macos=False)
    alerting.fire_alert("new_device", "192.168.1.1", "new", smtp_config={"host": "x", "to": "y"})
    assert len(fire_calls["email"]) == 1


def test_fire_alert_no_email_when_flag_off(alerting: Any, fire_calls: dict[str, list[Any]]) -> None:
    alerting.add_rule("R", "host_down", notify_email=False, notify_macos=True)
    alerting.fire_alert("host_down", "192.168.1.1", "down", smtp_config={"host": "x", "to": "y"})
    assert fire_calls["email"] == []
    assert len(fire_calls["macos"]) == 1
