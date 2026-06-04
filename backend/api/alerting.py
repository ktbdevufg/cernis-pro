"""FastAPI-Router der alerting-Domaene (v2, A.6) -- die REST-Pfade.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter, Ports und
``domain``-Typen werden hier NICHT importiert -- die Use-Cases kommen per FastAPI-
Dependency herein (Verdrahtung im Composition Root ``app.py``), und Domaenen-Objekte
(``AlertRule``/``AlertEvent``) werden ueber Attribut-Zugriff zu JSON serialisiert (Typ
``Any``, genau wie scanning ``_host_to_dict`` / monitoring ``_event_to_dict`` das halten).

Endpunkte (8, auf die 9 Use-Cases; Shapes am A.1-Characterization-Contract, mit den
bewussten v2-Abweichungen unten):

* ``GET    /api/alerts/rules``        -> ``GetAlertRules``    -> Liste der rules-View-dicts.
* ``POST   /api/alerts/rules``        -> ``AddAlertRule``     -> ``{"ok": True, "id": int}``.
* ``PATCH  /api/alerts/rules/{id}``   -> ``UpdateAlertRule``  -> ``{"ok": True}``.
* ``DELETE /api/alerts/rules/{id}``   -> ``DeleteAlertRule``  -> ``{"ok": True}``.
* ``GET    /api/alerts/history``      -> ``GetAlertHistory``  -> Liste der history-View-dicts.
* ``GET    /api/alerts/smtp``         -> ``GetSmtpConfigRaw`` + Redaktion am Rand.
* ``PUT    /api/alerts/smtp``         -> ``SaveSmtpConfig``   -> ``{"ok": True}``.
* ``POST   /api/alerts/test``         -> ``SendTestAlert``    -> 400/200/503, Logik am Rand.

(Der 9. Use-Case ``RaiseAlert`` hat KEINEN Endpunkt -- er wird erst von A.7 an den
monitor-Loop getriggert. Er wird hier dennoch verdrahtet bereitgestellt, damit A.7 ihn
ohne app.py-Aenderung konsumieren kann.)

AUFLAGE 1 -- WIRE-VERTRAG int 0/1 (A.1 ``test_alerting_rest_contract`` friert int ein):
Die rules-View MUSS ``enabled``/``notify_email``/``notify_macos`` als JSON-int 0/1 liefern.
Die Use-Cases/Domaene geben ``AlertRule`` mit BOOL (A.2). Die View am api-Rand konvertiert
``bool``->``int`` (``int(rule.enabled)`` etc.). Eine pydantic-bool-Response waere JSON
true/false = stiller Wire-Bruch -- darum ist ``_rule_to_dict`` ein dict-Bau am Rand
(``AlertRule`` via Attribut-Zugriff, Typ ``Any`` wie scanning ``_host_to_dict``), KEIN
pydantic-Response-Modell.

BEWUSSTE v2-ABWEICHUNGEN ggue. dem A.1-REST-Contract (API-Bruch erlaubt, CLAUDE.md):

* ``last_triggered`` ist aus der rules-View RAUS (Entscheidung 5). Es bleibt in Domaene +
  Tabelle (Cooldown braucht es), aber das Frontend liest es nicht (React-key ist der
  Array-Index, es ist Cooldown-intern). Mitschleppen riesse nichts auf -- es einfach
  nicht in die View aufnehmen.

* ``/api/alerts/history`` traegt KEIN ``id`` mehr (analog monitoring ``/events``): im
  Altcode war ``id`` die ``alert_history``-rowid (``SELECT *``); das v2-``AlertEvent``
  haelt kein ``id``-Feld, und das Frontend liest es nicht. ``datetime`` (``%Y-%m-%d
  %H:%M:%S``) bleibt (das Frontend rendert es) und wird HIER am Rand aus dem rohen
  ``timestamp`` formatiert -- nicht am Adapter (die ``recent()``-Query bleibt schlank,
  das Domaenen-Objekt unberuehrt).

AUFLAGE 2 -- SMTP-Redaktion exakt, Klartext/Cipher NIE in der Response:
``GET /smtp`` liest das ROHE dict (``GetSmtpConfigRaw`` -- Passwort = CIPHER) und
redigiert am Rand: ``password`` -> ``••••••••`` (exakt 8x U+2022) WENN ein Passwort da
ist, sonst ``""``; ``host``/``port``/``user``/``from``/``to`` roh durch. ``load_raw() ==
None`` (kein Setting) -> Altcode-GET-Form ``{"password": ""}`` (main.py:1071-1076: ``{}
or {}`` -> ``safe = {}`` + leeres Passwort).

AUFLAGE 3 -- ``/test`` 400/200/503-Logik am RAND (A.5-Entscheidung, HTTP-Belang):
1. ``GetSmtpConfigRaw()`` lesen. ``host`` ODER ``to`` leer/fehlt -> 400 mit dem festen
   Altcode-String (main.py:1100) + ``{"success": False, "log": [...]}``.
2. sonst ``SendTestAlert()`` -> ``EmailResult | None``. ``None`` (``load() == None``) ->
   auch 400 (beides "nicht versandfaehig", A.5-Entscheidung).
3. ``EmailResult.success`` -> 200, sonst 503. Body ``{"success": bool, "log": [str]}``.
Die host/to-Pruefung sitzt HIER (HTTP-Belang), NICHT im Use-Case (s. use_cases-Docstring).
"""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from application.alerting import (
    AddAlertRule,
    DeleteAlertRule,
    GetAlertHistory,
    GetAlertRules,
    GetSmtpConfigRaw,
    SaveSmtpConfig,
    SendTestAlert,
    UpdateAlertRule,
)

router = APIRouter(prefix="/api", tags=["alerting"])

# Redaktions-/Sentinel-String: exakt 8x U+2022 BULLET (A.1-Wortlaut, main.py:1075/1081).
# Der Adapter (SaveSmtpConfig) interpretiert denselben Wert beim PUT als "PW unveraendert".
_PASSWORD_REDACTED = "•" * 8

# Fester 400-String wie der Altcode-/test-Endpunkt (main.py:1100, em-dash U+2014).
_SMTP_NOT_CONFIGURED = "ERROR: SMTP not configured — set host and recipient address first"


# ── Body-Modelle (Hausmuster wie api/monitoring AddScheduleBody) ──────────────
# Optionale Felder mit Altcode-Defaults; ein leerer Body ist gueltig (POST nutzt die
# Defaults, PATCH laesst ``None`` = unveraendert). Kein rohes ``Body(dict)`` (B008 +
# untypisiert).


class AddRuleBody(BaseModel):
    """POST /api/alerts/rules -- alle Felder optional mit Altcode-``add_rule``-Defaults."""

    name: str = ""
    rule_type: str = "host_down"
    target: str = "any"
    threshold: int = 60
    notify_email: bool = False
    notify_macos: bool = True


class PatchRuleBody(BaseModel):
    """PATCH /api/alerts/rules/{id} -- ``None`` = Feld unveraendert lassen.

    ``enabled``/``name`` deckt die Altcode-Toggles ab (AlertsView schickt enabled als
    int 0/1 -> pydantic coerced zu bool, das Repo schreibt int 0/1 zurueck). ``target``/
    ``threshold``/``notify_*`` sind ebenfalls aenderbar (Altcode-update_rule-Whitelist).
    ``rule_type`` ist NICHT aenderbar (nicht in der Whitelist).
    """

    name: str | None = None
    target: str | None = None
    threshold: int | None = None
    notify_email: bool | None = None
    notify_macos: bool | None = None
    enabled: bool | None = None


class SmtpBody(BaseModel):
    """PUT /api/alerts/smtp -- die smtp_config-Keys (Altcode liest host/port/user/
    password/from/to). Alle optional mit Defaults; ``password == "••••••••"`` ist der
    Sentinel "PW unveraendert" (Adapter-Sache, s. SaveSmtpConfig/SettingsSmtpConfigAdapter).
    """

    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    from_addr: str = ""
    to: str = ""


# ── Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler. ──────────


def provide_get_alert_rules() -> GetAlertRules:
    raise NotImplementedError("GetAlertRules wird in app.py verdrahtet")


def provide_add_alert_rule() -> AddAlertRule:
    raise NotImplementedError("AddAlertRule wird in app.py verdrahtet")


def provide_update_alert_rule() -> UpdateAlertRule:
    raise NotImplementedError("UpdateAlertRule wird in app.py verdrahtet")


def provide_delete_alert_rule() -> DeleteAlertRule:
    raise NotImplementedError("DeleteAlertRule wird in app.py verdrahtet")


def provide_get_alert_history() -> GetAlertHistory:
    raise NotImplementedError("GetAlertHistory wird in app.py verdrahtet")


def provide_get_smtp_config_raw() -> GetSmtpConfigRaw:
    raise NotImplementedError("GetSmtpConfigRaw wird in app.py verdrahtet")


def provide_save_smtp_config() -> SaveSmtpConfig:
    raise NotImplementedError("SaveSmtpConfig wird in app.py verdrahtet")


def provide_send_test_alert() -> SendTestAlert:
    raise NotImplementedError("SendTestAlert wird in app.py verdrahtet")


# ── Serialisierungs-Helfer (Domaenen-Objekt -> Wire-dict am api-Rand) ─────────


def _rule_to_dict(rule: Any) -> dict[str, Any]:
    """``AlertRule`` -> Wire-dict. AUFLAGE 1: Flags ``bool``->``int`` 0/1.

    ``last_triggered`` ist bewusst RAUS (v2-Abweichung, Entscheidung 5 -- Cooldown-intern,
    das Frontend liest es nicht; s. Modul-Docstring). KEIN pydantic-Modell, damit die
    Flags als JSON-int 0/1 ueber die Wire gehen (nicht true/false).
    """
    return {
        "id": rule.id,
        "name": rule.name,
        "rule_type": rule.rule_type,
        "target": rule.target,
        "threshold": rule.threshold,
        "notify_email": int(rule.notify_email),
        "notify_macos": int(rule.notify_macos),
        "enabled": int(rule.enabled),
    }


def _event_to_dict(event: Any) -> dict[str, Any]:
    """``AlertEvent`` -> Wire-dict. ``ts`` roh, ``datetime`` hier formatiert.

    KEIN ``id`` (v2-Abweichung, analog monitoring ``/events`` -- die Altcode-rowid liest
    niemand; ``AlertEvent`` traegt kein ``id``). Felder wie die Altcode-history-Zeile
    minus ``id``: rule_id/rule_name/rule_type/target/message/ts/datetime.
    """
    return {
        "rule_id": event.rule_id,
        "rule_name": event.rule_name,
        "rule_type": event.rule_type,
        "target": event.target,
        "message": event.message,
        "ts": event.timestamp,
        "datetime": datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
    }


def _redact_smtp(raw: dict[str, Any] | None) -> dict[str, Any]:
    """AUFLAGE 2: das rohe smtp_config-dict fuer GET ``/smtp`` redigieren.

    Der Cipher darf den Rand erreichen, geht aber NIE in die Response: ``password`` wird
    zu ``••••••••`` (wenn ein Passwort da ist) bzw. ``""`` ersetzt; die uebrigen Felder
    (host/port/user/from/to) gehen roh durch. ``raw is None`` (kein Setting) -> Altcode-
    GET-Form ``{"password": ""}`` (main.py:1071-1076).
    """
    if raw is None:
        return {"password": ""}
    # Alle Felder ausser password roh durchreichen; password redigiert ans Ende.
    safe = {key: value for key, value in raw.items() if key != "password"}
    safe["password"] = _PASSWORD_REDACTED if raw.get("password") else ""
    return safe


# ── rules ─────────────────────────────────────────────────────────────────────


@router.get("/alerts/rules")
def get_alert_rules(
    get_rules: Annotated[GetAlertRules, Depends(provide_get_alert_rules)],
) -> list[dict[str, Any]]:
    """Alle Alert-Regeln. Flags als int 0/1 (Auflage 1), ohne ``last_triggered``."""
    return [_rule_to_dict(rule) for rule in get_rules()]


@router.post("/alerts/rules")
def add_alert_rule(
    add_rule: Annotated[AddAlertRule, Depends(provide_add_alert_rule)],
    body: AddRuleBody,
) -> dict[str, Any]:
    """Legt eine Regel an. Body-Felder optional mit Altcode-Defaults -> ``{ok, id}``."""
    rule_id = add_rule(
        name=body.name,
        rule_type=body.rule_type,
        target=body.target,
        threshold=body.threshold,
        notify_email=body.notify_email,
        notify_macos=body.notify_macos,
    )
    return {"ok": True, "id": rule_id}


@router.patch("/alerts/rules/{rule_id}")
def update_alert_rule(
    rule_id: int,
    update_rule: Annotated[UpdateAlertRule, Depends(provide_update_alert_rule)],
    body: PatchRuleBody,
) -> dict[str, bool]:
    """Aktualisiert die gesetzten Felder einer Regel (``None`` = unveraendert)."""
    update_rule(
        rule_id,
        name=body.name,
        target=body.target,
        threshold=body.threshold,
        notify_email=body.notify_email,
        notify_macos=body.notify_macos,
        enabled=body.enabled,
    )
    return {"ok": True}


@router.delete("/alerts/rules/{rule_id}")
def delete_alert_rule(
    rule_id: int,
    delete_rule: Annotated[DeleteAlertRule, Depends(provide_delete_alert_rule)],
) -> dict[str, bool]:
    """Loescht eine Regel. Idempotent bei fehlender id."""
    delete_rule(rule_id)
    return {"ok": True}


# ── history ───────────────────────────────────────────────────────────────────


@router.get("/alerts/history")
def get_alert_history(
    get_history: Annotated[GetAlertHistory, Depends(provide_get_alert_history)],
    limit: int = Query(default=50, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Die juengsten History-Ereignisse, neueste zuerst. KEIN ``id``, MIT ``datetime``."""
    return [_event_to_dict(event) for event in get_history(limit)]


# ── smtp ──────────────────────────────────────────────────────────────────────


@router.get("/alerts/smtp")
def get_smtp(
    get_raw: Annotated[GetSmtpConfigRaw, Depends(provide_get_smtp_config_raw)],
) -> dict[str, Any]:
    """SMTP-Config mit redigiertem Passwort (Auflage 2 -- Cipher/Klartext NIE in der Response)."""
    return _redact_smtp(get_raw())


@router.put("/alerts/smtp")
def set_smtp(
    save: Annotated[SaveSmtpConfig, Depends(provide_save_smtp_config)],
    body: SmtpBody,
) -> dict[str, bool]:
    """Speichert die SMTP-Config. Sentinel-/encrypt-Logik im Adapter (S7-Heilung).

    Das Wire-Feld heisst ``from`` (Python-Keyword) -- pydantic-Feld ``from_addr`` mit
    ``alias='from'`` waere eine Option; hier wird das rohe dict ueber ``by_alias`` nicht
    gebraucht, weil der Adapter die Keys ``host/port/user/password/from/to`` erwartet.
    Darum ``from_addr`` -> ``from`` beim dict-Bau am Rand abbilden.
    """
    config = {
        "host": body.host,
        "port": body.port,
        "user": body.user,
        "password": body.password,
        "from": body.from_addr,
        "to": body.to,
    }
    save(config)
    return {"ok": True}


# ── test (Send Test Alert) ─────────────────────────────────────────────────────


@router.post("/alerts/test")
async def test_alert(
    get_raw: Annotated[GetSmtpConfigRaw, Depends(provide_get_smtp_config_raw)],
    send_test: Annotated[SendTestAlert, Depends(provide_send_test_alert)],
) -> JSONResponse:
    """Versendet eine Test-E-Mail. 400/200/503-Logik am RAND (Auflage 3).

    Reihenfolge: rohes dict lesen -> host ODER to leer -> 400 (fester Altcode-String);
    sonst ``SendTestAlert`` -> ``None`` (nicht konfiguriert) -> auch 400; ``EmailResult``
    -> 200 bei ``success``, sonst 503.
    """
    raw = get_raw() or {}
    if not raw.get("host") or not raw.get("to"):
        return JSONResponse(
            status_code=400,
            content={"success": False, "log": [_SMTP_NOT_CONFIGURED]},
        )

    result = await send_test()
    if result is None:
        # load() == None trotz vorhandenem host/to (Race/leeres dict) -> nicht versandfaehig.
        return JSONResponse(
            status_code=400,
            content={"success": False, "log": [_SMTP_NOT_CONFIGURED]},
        )

    status_code = 200 if result.success else 503
    return JSONResponse(
        status_code=status_code,
        content={"success": result.success, "log": result.log},
    )
