"""Tests des resolver-PTR-Adapters -- reine Helfer + Tool-fehlt-Naht, kein echtes I/O.

Kein echter dig-/DNS-Aufruf: die reinen Helfer (``_first_ptr_name``/``_valid_ips``)
werden gegen realistische ``dig +short``-Beispielausgaben geprueft, der Adapter-Kern
laeuft gegen ein gemocktes ``_run_dig`` (kein Subprocess), und die Tool-fehlt-Naht wird
ueber gemocktes ``shutil.which`` belegt (``which`` None -> ``ResolverToolMissing``).
Mock-Muster wie in ``test_diagnostics_linux.py`` (``monkeypatch.setattr``).
"""

import asyncio
import shutil

import pytest

from infrastructure.resolver.dns_ptr import (
    DigDnsPtrResolver,
    _first_ptr_name,
    _valid_ips,
)
from infrastructure.resolver.errors import ResolverToolMissing

# ── Beispielausgaben (``dig +short``) ─────────────────────────────────────────

# ``dig +short -x 1.1.1.1`` -- ein PTR-Name mit abschliessendem Wurzel-Punkt.
_PTR_ONE = "one.one.one.one.\n"
# Mehrere PTR-Zeilen -- die erste gewinnt.
_PTR_MULTI = "first.example.com.\nsecond.example.com.\n"
# ``dig +short example.com A`` -- zwei A-Records.
_FWD_A = "104.20.23.154\n172.66.147.243\n"
# ``dig +short example.com AAAA`` -- ein AAAA-Record.
_FWD_AAAA = "2606:4700:10::6814:17fa\n"
# ``dig +short www.example.com A`` mit CNAME-Zwischenzeile (Name, keine IP).
_FWD_A_WITH_CNAME = "example.com.\n104.20.23.154\n"


# ── _first_ptr_name (reiner Helfer) ───────────────────────────────────────────


def test_first_ptr_name_strips_trailing_dot() -> None:
    assert _first_ptr_name(_PTR_ONE) == "one.one.one.one"


def test_first_ptr_name_takes_first_of_multiple() -> None:
    assert _first_ptr_name(_PTR_MULTI) == "first.example.com"


def test_first_ptr_name_empty_output_is_empty() -> None:
    assert _first_ptr_name("") == ""


# ── _valid_ips (reiner Helfer) ────────────────────────────────────────────────


def test_valid_ips_keeps_a_and_aaaa() -> None:
    assert _valid_ips(_FWD_A + _FWD_AAAA) == (
        "104.20.23.154",
        "172.66.147.243",
        "2606:4700:10::6814:17fa",
    )


def test_valid_ips_drops_cname_intermediate() -> None:
    # Die CNAME-Zwischenzeile (Name) ist kein IP-Literal -> verworfen.
    assert _valid_ips(_FWD_A_WITH_CNAME) == ("104.20.23.154",)


def test_valid_ips_dedups_stable_order() -> None:
    assert _valid_ips("1.2.3.4\n1.2.3.4\n5.6.7.8\n") == ("1.2.3.4", "5.6.7.8")


def test_valid_ips_empty_output_is_empty() -> None:
    assert _valid_ips("") == ()


# ── resolve_ptr (Adapter-Kern, gemocktes _run_dig/which) ──────────────────────


def test_resolve_ptr_hit_returns_name_without_dot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.resolver.dns_ptr._run_dig", lambda *_args: _PTR_ONE)
    assert asyncio.run(DigDnsPtrResolver().resolve_ptr("1.1.1.1")) == "one.one.one.one"


def test_resolve_ptr_no_entry_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Leere dig-Ausgabe (kein Eintrag/NXDOMAIN) -> "" (kein Fehler).
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.resolver.dns_ptr._run_dig", lambda *_args: "")
    assert asyncio.run(DigDnsPtrResolver().resolve_ptr("203.0.113.1")) == ""


def test_resolve_ptr_dig_failure_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ein scheiternder/Timeout-dig-Aufruf liefert "" (von _run_dig) -> "" (kein Fehler).
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.resolver.dns_ptr._run_dig", lambda *_args: "")
    assert asyncio.run(DigDnsPtrResolver().resolve_ptr("10.0.0.1")) == ""


def test_resolve_ptr_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(ResolverToolMissing) as exc_info:
        asyncio.run(DigDnsPtrResolver().resolve_ptr("1.1.1.1"))
    assert exc_info.value.tool == "dig"
    assert "dig" in exc_info.value.message


# ── resolve_forward (Adapter-Kern, gemocktes _run_dig/which) ──────────────────


def test_resolve_forward_combines_a_and_aaaa(monkeypatch: pytest.MonkeyPatch) -> None:
    # Erster Aufruf (A) -> _FWD_A, zweiter Aufruf (AAAA) -> _FWD_AAAA.
    outputs = iter([_FWD_A, _FWD_AAAA])
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.resolver.dns_ptr._run_dig", lambda *_args: next(outputs))
    result = asyncio.run(DigDnsPtrResolver().resolve_forward("example.com"))
    assert result == ("104.20.23.154", "172.66.147.243", "2606:4700:10::6814:17fa")


def test_resolve_forward_drops_cname_intermediate(monkeypatch: pytest.MonkeyPatch) -> None:
    # A-Antwort mit CNAME-Zwischenzeile, AAAA leer -> nur die gueltige IP bleibt.
    outputs = iter([_FWD_A_WITH_CNAME, ""])
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.resolver.dns_ptr._run_dig", lambda *_args: next(outputs))
    result = asyncio.run(DigDnsPtrResolver().resolve_forward("www.example.com"))
    assert result == ("104.20.23.154",)


def test_resolve_forward_no_hits_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.resolver.dns_ptr._run_dig", lambda *_args: "")
    assert asyncio.run(DigDnsPtrResolver().resolve_forward("nx.invalid")) == ()


def test_resolve_forward_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(ResolverToolMissing) as exc_info:
        asyncio.run(DigDnsPtrResolver().resolve_forward("example.com"))
    assert exc_info.value.tool == "dig"
