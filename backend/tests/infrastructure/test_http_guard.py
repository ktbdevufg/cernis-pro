"""Tests fuer die reine Origin-Prueffunktion ``is_origin_allowed`` (F-01, Etappe 1).

Reine Funktion ohne FastAPI/starlette -- ohne Server geprueft: erlaubt / fremd / None.
Sie ist die EINE Wahrheit hinter dem HTTP-Middleware-Guard und den drei WS-Handlern;
die Deckung hier haelt die Semantik-Regeln fest, die die Verdrahtung nur noch anruft.
"""

from infrastructure.http_guard import is_origin_allowed

_ALLOWED = [
    "tauri://localhost",
    "http://tauri.localhost",
    "http://localhost:1420",
    "http://localhost:5173",
]


# ── origin is None -> True (same-origin / Nicht-Browser, kein Angriffsvektor) ──


def test_none_origin_is_allowed() -> None:
    # Kein Origin-Header: same-origin-Requests und Nicht-Browser-Clients (Tauri-WebView
    # same-origin, curl, der Agent) -> durchlassen (Etappe 2 Token deckt den lokalen
    # Fremdprozess ab, NICHT der Origin-Guard).
    assert is_origin_allowed(None, _ALLOWED) is True


def test_none_origin_allowed_even_with_empty_allowlist() -> None:
    # None bleibt erlaubt, unabhaengig von der Allowlist -- es ist gar kein Cross-Origin.
    assert is_origin_allowed(None, []) is True


# ── origin in allowed -> True ────────────────────────────────────────────────


def test_allowed_origin_is_allowed() -> None:
    assert is_origin_allowed("http://localhost:5173", _ALLOWED) is True


def test_every_allowlisted_origin_is_allowed() -> None:
    # Jeder Default-Eintrag (Tauri v2 + Vite/Tauri-Dev) muss durchgehen -- bestehende
    # Clients bleiben unberuehrt.
    for origin in _ALLOWED:
        assert is_origin_allowed(origin, _ALLOWED) is True


# ── sonst -> False (fremde Browser-Herkunft) ─────────────────────────────────


def test_foreign_origin_is_rejected() -> None:
    assert is_origin_allowed("http://evil.example", _ALLOWED) is False


def test_any_origin_rejected_when_allowlist_empty() -> None:
    assert is_origin_allowed("http://localhost:5173", []) is False


def test_no_wildcard_or_prefix_matching() -> None:
    # Exakter String-Vergleich (CORS-Semantik hier): weder ein Sub-Origin noch ein
    # abweichender Port noch ein Schema-Wechsel matcht einen Allowlist-Eintrag.
    assert is_origin_allowed("http://localhost:5174", _ALLOWED) is False
    assert is_origin_allowed("https://localhost:5173", _ALLOWED) is False
    assert is_origin_allowed("http://evil.localhost:5173", _ALLOWED) is False
    assert is_origin_allowed("http://localhost:5173.evil.example", _ALLOWED) is False
