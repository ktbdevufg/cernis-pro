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
    provide_revoke_capture_access,
)
from api.capture_access import router as capture_access_router
from application.capture_access import (
    GetCaptureAccessStatus,
    GrantCaptureAccess,
    RevokeCaptureAccess,
)
from domain.capture_access import (
    CaptureAccessOutcome,
    CaptureAccessResult,
    CaptureAccessRevokeOutcome,
    CaptureAccessRevokeResult,
    CaptureAccessState,
    CaptureAccessStatus,
)

# ── Fake-Port: liefert die vorgegebenen Domaenenwerte ────────────────────────


class _FakeAccess:
    """``CaptureAccessPort``-Fake -- gibt zurueck, was der Test vorgibt.

    ``revoke`` merkt sich zusaetzlich den erhaltenen Modus in ``gesehene_modi``:
    daran laesst sich pruefen, dass der Rumpf-Wert wirklich bis zum Port durchkommt
    und nicht unterwegs verloren geht.
    """

    def __init__(
        self,
        status: CaptureAccessStatus,
        result: CaptureAccessResult,
        revoke_result: CaptureAccessRevokeResult,
    ) -> None:
        self._status = status
        self._result = result
        self._revoke_result = revoke_result
        self.gesehene_modi: list[bool] = []

    def status(self) -> CaptureAccessStatus:
        return self._status

    def grant(self) -> CaptureAccessResult:
        return self._result

    def revoke(self, nur_mitgliedschaft: bool) -> CaptureAccessRevokeResult:
        self.gesehene_modi.append(nur_mitgliedschaft)
        return self._revoke_result


def _build_fake(
    *,
    status: CaptureAccessStatus | None = None,
    result: CaptureAccessResult | None = None,
    revoke_result: CaptureAccessRevokeResult | None = None,
) -> _FakeAccess:
    """Fake-Port mit Vorgabewerten; Defaults sind jeweils der Erfolgsfall."""
    return _FakeAccess(
        status or CaptureAccessStatus(state=CaptureAccessState.GRANTED),
        result or CaptureAccessResult(outcome=CaptureAccessOutcome.GRANTED),
        revoke_result or CaptureAccessRevokeResult(outcome=CaptureAccessRevokeOutcome.REVOKED),
    )


def _client_fuer(fake: _FakeAccess) -> TestClient:
    """Frische App mit nur dem capture_access_router + verdrahteten Use-Cases."""
    app = FastAPI()
    app.include_router(capture_access_router)
    app.dependency_overrides[provide_get_capture_access_status] = lambda: GetCaptureAccessStatus(
        fake
    )
    app.dependency_overrides[provide_grant_capture_access] = lambda: GrantCaptureAccess(fake)
    app.dependency_overrides[provide_revoke_capture_access] = lambda: RevokeCaptureAccess(fake)
    return TestClient(app)


def _build_client(
    *,
    status: CaptureAccessStatus | None = None,
    result: CaptureAccessResult | None = None,
    revoke_result: CaptureAccessRevokeResult | None = None,
) -> TestClient:
    """Bequemer Weg fuer Tests, die den Fake selbst nicht brauchen."""
    return _client_fuer(_build_fake(status=status, result=result, revoke_result=revoke_result))


# ── GET /api/capture-access ─────────────────────────────────────────────────


def test_status_granted_wire_shape() -> None:
    """``GRANTED`` -> 200 ``{state: "granted", detail: "", members: []}``."""
    client = _build_client(status=CaptureAccessStatus(state=CaptureAccessState.GRANTED))

    resp = client.get("/api/capture-access")

    assert resp.status_code == 200
    assert resp.json() == {"state": "granted", "detail": "", "members": []}


def test_status_missing_carries_reason() -> None:
    """``MISSING`` -> 200 mit dem ehrlichen Grund im ``detail``-Feld."""
    client = _build_client(
        status=CaptureAccessStatus(state=CaptureAccessState.MISSING, detail="BPF nicht lesbar")
    )

    resp = client.get("/api/capture-access")

    assert resp.status_code == 200
    assert resp.json() == {"state": "missing", "detail": "BPF nicht lesbar", "members": []}


def test_status_members_are_a_json_list() -> None:
    """Das Domaenen-TUPLE kommt als JSON-LISTE an -- JSON kennt kein Tuple.

    Die Reihenfolge bleibt erhalten; die Oberflaeche zeigt daran, wer von einem
    vollstaendigen Widerruf mitbetroffen waere.
    """
    client = _build_client(
        status=CaptureAccessStatus(
            state=CaptureAccessState.GRANTED, members=("karl", "anna", "root")
        )
    )

    resp = client.get("/api/capture-access")

    assert resp.status_code == 200
    assert resp.json()["members"] == ["karl", "anna", "root"]


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


# ── POST /api/capture-access/revoke: Modus-Weitergabe + die Ausgaenge ───────


def test_revoke_success_wire_shape() -> None:
    """Erfolg -> 200 ``{outcome: "revoked", reason: ""}`` (nicht "granted")."""
    client = _build_client(
        revoke_result=CaptureAccessRevokeResult(outcome=CaptureAccessRevokeOutcome.REVOKED)
    )

    resp = client.post("/api/capture-access/revoke", json={"nur_mitgliedschaft": False})

    assert resp.status_code == 200
    assert resp.json() == {"outcome": "revoked", "reason": ""}


def test_revoke_passes_membership_only_flag_through() -> None:
    """``nur_mitgliedschaft=true`` erreicht den Port unveraendert.

    Ginge der Wert unterwegs verloren, wuerde ein schonender Widerruf still zu einem
    vollstaendigen -- den uebrigen Gruppenmitgliedern waere der Zugriff genommen,
    ohne dass jemand es bemerkt.
    """
    fake = _build_fake()
    client = _client_fuer(fake)

    client.post("/api/capture-access/revoke", json={"nur_mitgliedschaft": True})

    assert fake.gesehene_modi == [True]


def test_revoke_defaults_to_full_removal() -> None:
    """Ohne Feld im Rumpf gilt der vollstaendige Widerruf (Default ``False``)."""
    fake = _build_fake()
    client = _client_fuer(fake)

    resp = client.post("/api/capture-access/revoke", json={})

    assert resp.status_code == 200
    assert fake.gesehene_modi == [False]


def test_revoke_cancelled_is_distinguishable_and_not_an_error() -> None:
    """Abbruch -> 200 ``outcome="cancelled"``, unterscheidbar von ``failed``.

    Dieselbe Zusage wie bei ``grant``: kein HTTP-Fehlerstatus, damit die Oberflaeche
    einen ruhigen Hinweis statt einer Fehlermeldung zeigen kann.
    """
    client = _build_client(
        revoke_result=CaptureAccessRevokeResult(outcome=CaptureAccessRevokeOutcome.CANCELLED)
    )

    resp = client.post("/api/capture-access/revoke", json={})

    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "cancelled"
    assert body["outcome"] != "failed"
    assert body["reason"] == ""


def test_revoke_failed_carries_reason() -> None:
    """Fehlschlag -> 200 ``outcome="failed"`` MIT verstaendlichem Grund."""
    client = _build_client(
        revoke_result=CaptureAccessRevokeResult(
            outcome=CaptureAccessRevokeOutcome.FAILED, reason="Gruppe nicht loeschbar"
        )
    )

    resp = client.post("/api/capture-access/revoke", json={})

    assert resp.status_code == 200
    assert resp.json() == {"outcome": "failed", "reason": "Gruppe nicht loeschbar"}


def test_all_four_revoke_outcomes_are_distinct_on_the_wire() -> None:
    """Alle vier Widerrufs-Ausgaenge liefern VERSCHIEDENE ``outcome``-Strings."""
    gesehen = set()
    for outcome in CaptureAccessRevokeOutcome:
        client = _build_client(revoke_result=CaptureAccessRevokeResult(outcome=outcome))
        gesehen.add(client.post("/api/capture-access/revoke", json={}).json()["outcome"])

    assert gesehen == {"revoked", "cancelled", "failed", "not_applicable"}
