"""Origin-Guard end-to-end an der real gebauten App (F-01, Etappe 1).

Prueft die BaseHTTPMiddleware (zustandsaendernde HTTP-Methoden) UND den WS-Handshake-
Guard gegen die echte ``create_app``-Verdrahtung -- nicht gegen ein Mini-Stub. So ist
die Reihenfolge (Guard vs. CORS vs. Route) und die Durchreichung der Allowlist
(``cfg.cors_allow_origins`` -> Middleware + WS-Factories) mitgetestet.

Als state-changing Sonde dient ``POST /api/analysis/acknowledge`` mit einem UNGUELTIGEN
Body: eine erlaubte/fehlende Origin laeuft in die Pydantic-Validierung (422 -- die Route
IST erreicht, kein Handler-Seiteneffekt), eine fremde Origin wird schon vom Guard mit 403
gestoppt (die Route wird nie erreicht). So bleibt der Test frei von DB-Schreib-Effekten.
"""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

# Eine der Default-Allowlist-Origins (Vite-Dev) -- steht in cfg.cors_allow_origins.
_ALLOWED_ORIGIN = "http://localhost:5173"
_FOREIGN_ORIGIN = "http://evil.example"

# State-changing Sonde: erwartet einen Body -> ungueltiger Body ergibt 422, sobald die
# Route erreicht ist. Vor der Route greift der Origin-Guard (bei fremder Origin -> 403).
_POST_PROBE = "/api/analysis/acknowledge"


# ── HTTP-Middleware: zustandsaendernde Methoden ──────────────────────────────


def test_foreign_origin_on_post_is_rejected_403(client: TestClient) -> None:
    # Fremde Browser-Herkunft auf einem POST -> 403, ehrlicher Body, Route NICHT erreicht
    # (sonst waere es 422 aus der Body-Validierung).
    response = client.post(_POST_PROBE, json={}, headers={"origin": _FOREIGN_ORIGIN})

    assert response.status_code == 403
    assert response.json() == {"detail": "Origin nicht erlaubt."}


def test_allowed_origin_on_post_reaches_route(client: TestClient) -> None:
    # Erlaubte Origin -> der Guard laesst durch, die Route wird erreicht. Der ungueltige
    # Body ergibt 422 (Pydantic) -- entscheidend ist: NICHT 403, der Guard hat durchgelassen.
    response = client.post(_POST_PROBE, json={}, headers={"origin": _ALLOWED_ORIGIN})

    assert response.status_code != 403
    assert response.status_code == 422


def test_missing_origin_on_post_reaches_route(client: TestClient) -> None:
    # Kein Origin-Header (same-origin / Nicht-Browser-Client) -> durchgelassen (kein
    # Cross-Origin-Angriffsvektor). Route erreicht -> 422 aus der Body-Validierung.
    response = client.post(_POST_PROBE, json={})

    assert response.status_code != 403
    assert response.status_code == 422


def test_get_with_foreign_origin_is_not_guarded(client: TestClient) -> None:
    # Lesezugriffe (GET) bleiben unberuehrt -- der Guard prueft nur zustandsaendernde
    # Methoden. Ein GET mit fremder Origin muss normal durchgehen.
    response = client.get("/health", headers={"origin": _FOREIGN_ORIGIN})

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ── WS-Handshake-Guard ───────────────────────────────────────────────────────


def test_foreign_origin_on_ws_scan_closed_with_1008(client: TestClient) -> None:
    # Fremde Origin auf /ws/scan -> der Handler schliesst VOR accept() mit 1008; der
    # TestClient meldet das als WebSocketDisconnect. Es kommt KEIN Scan-Frame durch.
    with (
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect("/ws/scan", headers={"origin": _FOREIGN_ORIGIN}) as ws,
    ):
        ws.receive_json()

    assert exc_info.value.code == 1008


def test_allowed_origin_on_ws_scan_connects(client: TestClient) -> None:
    # Erlaubte Origin auf /ws/scan -> Handshake kommt zustande (kein 1008). Ein
    # ungueltiges CIDR ergibt einen error-Frame -- der Beweis, dass der Handler LAEUFT
    # (der Guard hat durchgelassen, accept() ist passiert).
    with client.websocket_connect("/ws/scan", headers={"origin": _ALLOWED_ORIGIN}) as ws:
        ws.send_json({"cidr": "nonsense"})
        frame = ws.receive_json()

    assert frame["type"] == "error"
