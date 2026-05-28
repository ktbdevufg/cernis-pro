"""FastAPI-Router der settings-Domaene (v2).

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich die Use-Cases aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter werden
hier NICHT importiert -- die Use-Cases kommen per FastAPI-Dependency herein und
werden im Composition Root (``app.py``) verdrahtet.

HTTP-Mapping der Application-Fehler passiert hier (nicht in der Application):
Routing-Verstoesse (falsches Backend) und ungueltige Keys -> 400. Der
Keystore-Ausfall (``SecretStoreUnavailableError``) ist infrastruktur-nah und
liegt ausserhalb dessen, was api importieren darf; er wird als Querschnitt im
Composition Root auf 503 gemappt (ADR 0001: kein stiller Erfolg).
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from application.settings import (
    GetSettings,
    NotASecretKeyError,
    SecretKeyNotAllowedError,
    UpdateSecret,
    UpdateSetting,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit
# echten Adaptern verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler -- kein
# stiller Fallback.
def provide_get_settings() -> GetSettings:
    raise NotImplementedError("GetSettings wird in app.py verdrahtet")


def provide_update_setting() -> UpdateSetting:
    raise NotImplementedError("UpdateSetting wird in app.py verdrahtet")


def provide_update_secret() -> UpdateSecret:
    raise NotImplementedError("UpdateSecret wird in app.py verdrahtet")


class SettingBody(BaseModel):
    """Body fuer ein Nicht-Secret-Setting: beliebiger JSON-Wert."""

    value: Any


class SecretBody(BaseModel):
    """Body fuer ein Secret: leerer/fehlender Wert loescht (idempotent)."""

    value: str | None = None


@router.get("")
def read_settings(
    get_settings: Annotated[GetSettings, Depends(provide_get_settings)],
) -> dict[str, Any]:
    """Alle Settings; Secrets maskiert (REDACTED) bzw. weggelassen -- nie Klartext."""
    return get_settings()


@router.put("/{key}")
def put_setting(
    key: str,
    body: SettingBody,
    update_setting: Annotated[UpdateSetting, Depends(provide_update_setting)],
) -> dict[str, bool]:
    """Schreibt ein Nicht-Secret. Secret-Keys werden abgelehnt (400)."""
    try:
        update_setting(key, body.value)
    except SecretKeyNotAllowedError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dieser Key ist ein Secret und gehoert ueber /api/settings/secrets/{key}.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ungueltiger Setting-Key.",
        ) from exc
    return {"ok": True}


@router.put("/secrets/{key}")
def put_secret(
    key: str,
    body: SecretBody,
    update_secret: Annotated[UpdateSecret, Depends(provide_update_secret)],
) -> dict[str, bool]:
    """Setzt oder loescht ein Secret (nur SECRET_KEYS). Nicht-Secret-Key -> 400."""
    try:
        update_secret(key, body.value)
    except NotASecretKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dieser Key ist kein Secret.",
        ) from exc
    return {"ok": True}
