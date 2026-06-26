"""FastAPI-Router der blocklist-Domaene (v2), prefix ``/api/blocklist``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/maintenance.py``/``api/report.py`` kennt
dieser Router WEDER ``application`` NOCH ``domain`` NOCH ``infrastructure`` (import-linter
Regel 4): alle Runner kommen als ``Callable`` bzw. schmale lokale ``Protocol``-Vertraege
per Dependency herein, verdrahtet im Composition Root (``app.py``). Die Projektion
Domaene->Wire macht der Composition-Root-Runner in ``app.py``, NICHT dieser Router.

Provider-Marker (``provide_*`` -> ``NotImplementedError``): ohne Verdrahtung bewusst ein
lauter Fehler (kein stiller Fallback, S3). Eigene pydantic ``*Out``/``*Body``-Modelle
(snake_case Wire). Vokabular-Hebung (group/fmt/strictness) passiert im Use-Case; ein
Fehlwert wirft dort ``ValueError`` (Application-``BlocklistError`` ist eine Unterklasse) ->
hier auf 422 gemappt. Unbekannte id bei PATCH/DELETE-naher Logik -> 404. 422/404 als
NACKTE Literale (Bestandsmuster ``api/monitoring.py``).
"""

from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


# ── Wire-Modelle (eigene Form, KEIN application/domain-Typ) ────────────────────


class SourceOut(BaseModel):
    """Eine Quellen-Definition in Wire-Form (Projektion macht der Composition Root)."""

    id: str
    name: str
    group: str
    fmt: str
    origin: str
    url: str | None
    license: str
    attribution_required: bool
    enabled: bool
    last_fetched_ts: float | None
    status: str
    entry_count: int | None


class AddSourceBody(BaseModel):
    """POST /sources -- neue Nutzer-Quelle per URL. group/fmt roh (Hebung im Use-Case)."""

    name: str
    url: str
    group: str
    fmt: str


class AddSourceOut(BaseModel):
    """Ergebnis von POST /sources: vergebene id + freundlicher Lizenz-Hinweis (oder null)."""

    source_id: str
    license_hint: str | None


class UploadSourceBody(BaseModel):
    """POST /sources/upload -- hochgeladene Liste. ``content`` ist der rohe Listentext."""

    name: str
    group: str
    fmt: str
    content: str


class UploadSourceOut(BaseModel):
    """Ergebnis von POST /sources/upload: vergebene id + Zahl sofort geparster Eintraege."""

    source_id: str
    entry_count: int


class UpdateSourceBody(BaseModel):
    """PATCH /sources/{id} -- partielles Update; alle Felder optional (None = unveraendert)."""

    name: str | None = None
    url: str | None = None
    group: str | None = None
    fmt: str | None = None
    enabled: bool | None = None


class RefreshOut(BaseModel):
    """Ergebnis eines Lade-Laufs (POST /sources/{id}/refresh)."""

    source_id: str
    ok: bool
    entry_count: int | None
    error: str | None


class RefreshDueOut(BaseModel):
    """Ergebnis von POST /refresh-due: die Lade-Ergebnisse aller faelligen Quellen."""

    results: list[RefreshOut]


class HealthIssueOut(BaseModel):
    """Ein Gesundheits-Befund in Wire-Form (BROKEN-Quelle + optionaler Ersatzvorschlag)."""

    source_id: str
    name: str
    group: str
    suggested_replacement_id: str | None


class HealthOut(BaseModel):
    """Ergebnis von GET /health: die Liste der Gesundheits-Befunde."""

    issues: list[HealthIssueOut]


class SettingsOut(BaseModel):
    """Ergebnis von GET /settings: Strenge + Refresh-Intervall + Gruppen-Schalter."""

    strictness: str
    refresh_interval_days: int
    group_tracker_ads_enabled: bool
    group_threat_enabled: bool


class SettingsBody(BaseModel):
    """PUT /settings -- alle Felder optional (nur gesetzte werden geschrieben)."""

    strictness: str | None = None
    refresh_interval_days: int | None = None
    group_tracker_ads_enabled: bool | None = None
    group_threat_enabled: bool | None = None


class ContactInputBody(BaseModel):
    """Ein abzugleichender Aussenkontakt im Wire-Body von POST /match."""

    remote_ip: str
    hostname: str | None = None


class MatchBody(BaseModel):
    """POST /match -- Kontakte + optionale Strenge (fehlt sie, liest der Runner Settings)."""

    contacts: list[ContactInputBody]
    strictness: str | None = None


class MatchOut(BaseModel):
    """Ein Treffer in Wire-Form (Quelle + Wert, auf den getroffen wurde)."""

    source_id: str
    source_name: str
    group: str
    matched_on: str


class ContactMatchOut(BaseModel):
    """Das Abgleich-Ergebnis EINES Kontakts (auch leere ``matches`` zulaessig)."""

    remote_ip: str
    hostname: str | None
    matches: list[MatchOut]


class MatchResultsOut(BaseModel):
    """Ergebnis von POST /match: je Eingangs-Kontakt ein ``ContactMatchOut``."""

    results: list[ContactMatchOut]


# ── injizierte Composition-Root-Runner (Marker + schmale Vertraege) ────────────
# Provider-Marker: in app.py per dependency_overrides verdrahtet. Ohne Verdrahtung
# bewusst ein lauter Fehler (kein stiller Fallback, S3).


class AddSourceRunner(Protocol):
    """Schmaler Vertrag des injizierten Add-Runners (rohe Strings rein, Wire-Out raus).

    Die group/fmt-Hebung passiert im Use-Case; ein Fehlwert wirft ``ValueError``
    (Application-``BlocklistError`` ist Unterklasse) -> der Endpunkt mappt auf 422.
    """

    def __call__(self, body: AddSourceBody) -> AddSourceOut:
        """Legt die Quelle an und liefert id + Lizenz-Hinweis (Wire-Form)."""
        ...


class UploadSourceRunner(Protocol):
    """Schmaler Vertrag des injizierten Upload-Runners (parst sofort, Wire-Out raus)."""

    def __call__(self, body: UploadSourceBody) -> UploadSourceOut:
        """Importiert die hochgeladene Liste und liefert id + Eintragszahl."""
        ...


class UpdateSourceRunner(Protocol):
    """Schmaler Vertrag des injizierten Update-Runners (partielles Update).

    Unbekannte id wirft ``KeyError`` (der Composition-Root-Runner uebersetzt den
    Use-Case-Fehler in ``KeyError``) -> 404; ein Vokabular-Fehlwert wirft ``ValueError``
    -> 422.
    """

    def __call__(self, source_id: str, body: UpdateSourceBody) -> None:
        """Aktualisiert die Quelle partiell (nur gesetzte Felder)."""
        ...


class DeleteSourceRunner(Protocol):
    """Schmaler Vertrag des injizierten Delete-Runners (idempotent)."""

    def __call__(self, source_id: str) -> None:
        """Loescht die Quelle samt Eintraegen (idempotent)."""
        ...


class RefreshSourceRunner(Protocol):
    """Schmaler Vertrag des injizierten Einzel-Refresh-Runners.

    Unbekannte id / Upload-ohne-url wirft ``KeyError`` -> 404; ein Download-/Parse-Fehler
    ist KEIN HTTP-Fehler -> er kommt als ``RefreshOut(ok=False, ...)`` zurueck.
    """

    def __call__(self, source_id: str) -> RefreshOut:
        """Laedt EINE Quelle und liefert das Lade-Ergebnis (Wire-Form)."""
        ...


class MatchRunner(Protocol):
    """Schmaler Vertrag des injizierten Match-Runners (Strenge aus Body ODER Settings).

    Eine im Body angegebene, aber unbekannte Strenge wirft ``ValueError`` -> 422.
    """

    def __call__(self, body: MatchBody) -> MatchResultsOut:
        """Gleicht die Kontakte ab und liefert je Kontakt das Treffer-Ergebnis."""
        ...


class SettingsWriteRunner(Protocol):
    """Schmaler Vertrag des injizierten Settings-Schreib-Runners.

    Eine unbekannte Strenge im Body wirft ``ValueError`` -> 422.
    """

    def __call__(self, body: SettingsBody) -> None:
        """Schreibt die gesetzten Settings-Felder (Strenge wird validiert)."""
        ...


# Lese-Runner als reine Callables (liefern die fertige Wire-Sicht).
type SourceListProvider = Callable[[], Callable[[], list[SourceOut]]]
type HealthProvider = Callable[[], Callable[[], HealthOut]]
type SettingsReadProvider = Callable[[], Callable[[], SettingsOut]]
type RefreshDueProvider = Callable[[], Callable[[], RefreshDueOut]]
type ResetDefaultsProvider = Callable[[], Callable[[], None]]


def provide_list_sources() -> Callable[[], list[SourceOut]]:
    raise NotImplementedError("list_sources wird in app.py verdrahtet")


def provide_add_source() -> AddSourceRunner:
    raise NotImplementedError("AddSourceRunner wird in app.py verdrahtet")


def provide_upload_source() -> UploadSourceRunner:
    raise NotImplementedError("UploadSourceRunner wird in app.py verdrahtet")


def provide_update_source() -> UpdateSourceRunner:
    raise NotImplementedError("UpdateSourceRunner wird in app.py verdrahtet")


def provide_delete_source() -> DeleteSourceRunner:
    raise NotImplementedError("DeleteSourceRunner wird in app.py verdrahtet")


def provide_refresh_source() -> RefreshSourceRunner:
    raise NotImplementedError("RefreshSourceRunner wird in app.py verdrahtet")


def provide_refresh_due() -> Callable[[], RefreshDueOut]:
    raise NotImplementedError("refresh_due wird in app.py verdrahtet")


def provide_reset_defaults() -> Callable[[], None]:
    raise NotImplementedError("reset_defaults wird in app.py verdrahtet")


def provide_health() -> Callable[[], HealthOut]:
    raise NotImplementedError("health wird in app.py verdrahtet")


def provide_read_settings() -> Callable[[], SettingsOut]:
    raise NotImplementedError("read_settings wird in app.py verdrahtet")


def provide_write_settings() -> SettingsWriteRunner:
    raise NotImplementedError("SettingsWriteRunner wird in app.py verdrahtet")


def provide_match() -> MatchRunner:
    raise NotImplementedError("MatchRunner wird in app.py verdrahtet")


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("/sources")
def list_sources(
    runner: Annotated[Callable[[], list[SourceOut]], Depends(provide_list_sources)],
) -> list[SourceOut]:
    """Liefert alle Quellen-Definitionen (Wire-Form; Projektion im Composition Root)."""
    return runner()


@router.post("/sources")
def add_source(
    body: AddSourceBody,
    runner: Annotated[AddSourceRunner, Depends(provide_add_source)],
) -> AddSourceOut:
    """Legt eine Nutzer-Quelle per URL an. group/fmt ungueltig -> 422 (Use-Case wirft)."""
    try:
        return runner(body)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@router.post("/sources/upload")
def upload_source(
    body: UploadSourceBody,
    runner: Annotated[UploadSourceRunner, Depends(provide_upload_source)],
) -> UploadSourceOut:
    """Importiert eine hochgeladene Liste (parst sofort). group/fmt ungueltig -> 422."""
    try:
        return runner(body)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@router.patch("/sources/{source_id}")
def update_source(
    source_id: str,
    body: UpdateSourceBody,
    runner: Annotated[UpdateSourceRunner, Depends(provide_update_source)],
) -> dict[str, bool]:
    """Partielles Update. Unbekannte id -> 404; Vokabular-Fehlwert -> 422."""
    try:
        runner(source_id, body)
    except KeyError as exc:
        raise HTTPException(404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return {"ok": True}


@router.delete("/sources/{source_id}")
def delete_source(
    source_id: str,
    runner: Annotated[DeleteSourceRunner, Depends(provide_delete_source)],
) -> dict[str, bool]:
    """Loescht eine Quelle samt Eintraegen (idempotent)."""
    runner(source_id)
    return {"ok": True}


@router.post("/sources/{source_id}/refresh")
def refresh_source(
    source_id: str,
    runner: Annotated[RefreshSourceRunner, Depends(provide_refresh_source)],
) -> RefreshOut:
    """Laedt EINE Quelle. Unbekannte id / Upload-ohne-url -> 404.

    Ein Download-/Parse-Fehler ist KEIN HTTP-Fehler: er kommt als
    ``RefreshOut(ok=False, error=...)`` zurueck (status BROKEN, der Health-Check
    verarbeitet ihn).
    """
    try:
        return runner(source_id)
    except KeyError as exc:
        raise HTTPException(404, detail=str(exc)) from exc


@router.post("/refresh-due")
def refresh_due(
    runner: Annotated[Callable[[], RefreshDueOut], Depends(provide_refresh_due)],
) -> RefreshDueOut:
    """Manueller "alle faelligen jetzt": refresht die faelligen Quellen (Intervall aus Settings)."""
    return runner()


@router.post("/reset-defaults")
def reset_defaults(
    runner: Annotated[Callable[[], None], Depends(provide_reset_defaults)],
) -> dict[str, bool]:
    """Werkszustand der Listen: leert + legt alle Werksquellen neu an."""
    runner()
    return {"ok": True}


@router.get("/health")
def health(
    runner: Annotated[Callable[[], HealthOut], Depends(provide_health)],
) -> HealthOut:
    """Liefert je BROKEN-Quelle einen Befund + optionalen Ersatzvorschlag."""
    return runner()


@router.get("/settings")
def read_settings(
    runner: Annotated[Callable[[], SettingsOut], Depends(provide_read_settings)],
) -> SettingsOut:
    """Liefert Strenge + Refresh-Intervall + Gruppen-Schalter (Defaults bei leerer DB)."""
    return runner()


@router.put("/settings")
def write_settings(
    body: SettingsBody,
    runner: Annotated[SettingsWriteRunner, Depends(provide_write_settings)],
) -> dict[str, bool]:
    """Schreibt die gesetzten Settings-Felder. Strenge ungueltig -> 422."""
    try:
        runner(body)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return {"ok": True}


@router.post("/match")
def match(
    body: MatchBody,
    runner: Annotated[MatchRunner, Depends(provide_match)],
) -> MatchResultsOut:
    """Gleicht Aussenkontakte gegen die aktiven Listen ab. Strenge ungueltig -> 422.

    Fehlt ``strictness`` im Body, liest der Composition-Root-Runner sie aus den Settings;
    die Gruppen-Feinschalter aus den Settings fliessen ebenfalls ein.
    """
    try:
        return runner(body)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
