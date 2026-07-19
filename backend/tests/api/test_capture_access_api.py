"""End-to-end-Tests der Capture-Rechte-API (Etappe 2) gegen den capture_access_router.

Frische ``FastAPI`` mit NUR diesem Router; die ``provide_*`` werden per
``dependency_overrides`` mit echten Use-Cases auf einem Fake-Port verdrahtet -- kein
osascript, kein Skript, keine Systemrechte.

Der Kern der Tests ist die Zusage an das Frontend: die drei Ausgaenge der Einrichtung
(``granted`` / ``cancelled`` / ``failed``) muessen in der Wire-Form UNTERSCHEIDBAR
ankommen, und ein Abbruch darf kein HTTP-Fehler sein -- sonst zeigt die Oberflaeche
dafuer Fehleroptik, obwohl der Nutzer sich nur legitim anders entschieden hat (S3).
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.capture_access import (
    provide_get_capture_access_status,
    provide_grant_capture_access,
)
from api.capture_access import router as capture_access_router
from application.capture_access import GetCaptureAccessStatus, GrantCaptureAccess
from domain.capture_access import (
    CaptureAccessOutcome,
    CaptureAccessResult,
    CaptureAccessState,
    CaptureAccessStatus,
)

# ── Fake-Port: liefert die vorgegebenen Domaenenwerte ────────────────────────


class _FakeAccess:
    """``CaptureAccessPort``-Fake -- gibt zurueck, was der Test vorgibt."""

    def __init__(self, status: CaptureAccessStatus, result: CaptureAccessResult) -> None:
        self._status = status
        self._result = result

    def status(self) -> CaptureAccessStatus:
        return self._status

    def grant(self) -> CaptureAccessResult:
        return self._result


def _build_client(
    *,
    status: CaptureAccessStatus | None = None,
    result: CaptureAccessResult | None = None,
) -> TestClient:
    """Frische App mit nur dem capture_access_router + verdrahteten Use-Cases."""
    fake = _FakeAccess(
        status or CaptureAccessStatus(state=CaptureAccessState.GRANTED),
        result or CaptureAccessResult(outcome=CaptureAccessOutcome.GRANTED),
    )
    app = FastAPI()
    app.include_router(capture_access_router)
    app.dependency_overrides[provide_get_capture_access_status] = lambda: GetCaptureAccessStatus(
        fake
    )
    app.dependency_overrides[provide_grant_capture_access] = lambda: GrantCaptureAccess(fake)
    return TestClient(app)


# ── GET /api/capture-access ─────────────────────────────────────────────────


def test_status_granted_wire_shape() -> None:
    """``GRANTED`` -> 200 ``{state: "granted", detail: ""}``."""
    client = _build_client(status=CaptureAccessStatus(state=CaptureAccessState.GRANTED))

    resp = client.get("/api/capture-access")

    assert resp.status_code == 200
    assert resp.json() == {"state": "granted", "detail": ""}


def test_status_missing_carries_reason() -> None:
    """``MISSING`` -> 200 mit dem ehrlichen Grund im ``detail``-Feld."""
    client = _build_client(
        status=CaptureAccessStatus(state=CaptureAccessState.MISSING, detail="BPF nicht lesbar")
    )

    resp = client.get("/api/capture-access")

    assert resp.status_code == 200
    assert resp.json() == {"state": "missing", "detail": "BPF nicht lesbar"}


def test_status_not_applicable_is_not_an_error() -> None:
    """Nicht-macOS -> 200 ``not_applicable`` (ehrliche Auskunft, KEIN HTTP-Fehler)."""
    client = _build_client(
        status=CaptureAccessStatus(state=CaptureAccessState.NOT_APPLICABLE, detail="nur macOS")
    )

    resp = client.get("/api/capture-access")

    assert resp.status_code == 200
    assert resp.json()["state"] == "not_applicable"


# ── POST /api/capture-access/grant: die drei Ausgaenge ──────────────────────


def test_grant_success_wire_shape() -> None:
    """Erfolg -> 200 ``{outcome: "granted", reason: ""}``."""
    client = _build_client(result=CaptureAccessResult(outcome=CaptureAccessOutcome.GRANTED))

    resp = client.post("/api/capture-access/grant")

    assert resp.status_code == 200
    assert resp.json() == {"outcome": "granted", "reason": ""}


def test_grant_cancelled_is_distinguishable_and_not_an_error() -> None:
    """Abbruch -> 200 ``outcome="cancelled"``, unterscheidbar von ``failed``.

    Die zentrale Frontend-Zusage: kein HTTP-Fehlerstatus und ein eigener Wert, damit
    die Oberflaeche einen ruhigen Hinweis statt einer Fehlermeldung zeigen kann.
    """
    client = _build_client(result=CaptureAccessResult(outcome=CaptureAccessOutcome.CANCELLED))

    resp = client.post("/api/capture-access/grant")

    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "cancelled"
    assert body["outcome"] != "failed"
    assert body["reason"] == ""


def test_grant_failed_carries_reason() -> None:
    """Fehlschlag -> 200 ``outcome="failed"`` MIT verstaendlichem Grund."""
    client = _build_client(
        result=CaptureAccessResult(
            outcome=CaptureAccessOutcome.FAILED, reason="Gruppe nicht anlegbar"
        )
    )

    resp = client.post("/api/capture-access/grant")

    assert resp.status_code == 200
    assert resp.json() == {"outcome": "failed", "reason": "Gruppe nicht anlegbar"}


def test_grant_not_applicable_wire_shape() -> None:
    """Nicht-macOS -> 200 ``not_applicable`` mit Begruendung, kein Fehler."""
    client = _build_client(
        result=CaptureAccessResult(outcome=CaptureAccessOutcome.NOT_APPLICABLE, reason="nur macOS")
    )

    resp = client.post("/api/capture-access/grant")

    assert resp.status_code == 200
    assert resp.json()["outcome"] == "not_applicable"


def test_all_four_outcomes_are_distinct_on_the_wire() -> None:
    """Alle vier Ausgaenge liefern VERSCHIEDENE ``outcome``-Strings.

    Faellt je einer mit einem anderen zusammen, kann das Frontend sie nicht mehr
    unterscheiden -- genau das soll dieser Test verhindern.
    """
    gesehen = set()
    for outcome in CaptureAccessOutcome:
        client = _build_client(result=CaptureAccessResult(outcome=outcome))
        gesehen.add(client.post("/api/capture-access/grant").json()["outcome"])

    assert gesehen == {"granted", "cancelled", "failed", "not_applicable"}
