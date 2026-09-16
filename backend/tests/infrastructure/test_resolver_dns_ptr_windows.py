"""Tests des Windows-resolver-PTR-Adapters -- reine Helfer + Adapter-Kern, kein echtes I/O.

Kein echter DNS-Aufruf: die reinen Helfer (``_first_ptr_name``/``_valid_ips``) werden gegen
realistische dnspython-Antwort-Strings geprueft, und der Adapter-Kern laeuft gegen ein
gemocktes ``_query_names`` (kein Netz). Zusaetzlich wird ueber ein gemocktes
``dns.resolver.resolve`` belegt, dass ``_query_names`` bei jeglichem ``DNSException``
(NXDOMAIN, NoAnswer, NoNameservers, Timeout) den gueltigen Leer-Zustand liefert -- exakt das
Verhalten eines scheiternden/leeren dig-Aufrufs im Linux-Adapter.

Plattformunabhaengig: ``dnspython`` ist plattformneutral, der Adapter hat KEINEN
``sys.platform``-Guard -- diese Tests laufen deterministisch auch auf dem Linux-CI-Runner.
Mock-Muster wie in ``test_resolver_dns_ptr.py`` (``monkeypatch.setattr``).
"""

import asyncio

import dns.exception
import dns.resolver
import pytest

from infrastructure.resolver.dns_ptr_windows import (
    DnspythonPtrResolver,
    _first_ptr_name,
    _query_names,
    _valid_ips,
)

# ── Beispielantworten (dnspython liefert je Rdata einen str) ──────────────────

# PTR-Namen mit abschliessendem Wurzel-Punkt (wie ``str(PTR-Rdata)``).
_PTR_ONE = ["one.one.one.one."]
# Mehrere PTR-Antworten -- die erste gewinnt.
_PTR_MULTI = ["first.example.com.", "second.example.com."]
# A-Records.
_FWD_A = ["104.20.23.154", "172.66.147.243"]
# AAAA-Record.
_FWD_AAAA = ["2606:4700:10::6814:17fa"]


# ── _first_ptr_name (reiner Helfer) ───────────────────────────────────────────


def test_first_ptr_name_strips_trailing_dot() -> None:
    assert _first_ptr_name(_PTR_ONE) == "one.one.one.one"


def test_first_ptr_name_takes_first_of_multiple() -> None:
    assert _first_ptr_name(_PTR_MULTI) == "first.example.com"


def test_first_ptr_name_empty_list_is_empty() -> None:
    assert _first_ptr_name([]) == ""


# ── _valid_ips (reiner Helfer) ────────────────────────────────────────────────


def test_valid_ips_keeps_a_and_aaaa() -> None:
    assert _valid_ips(_FWD_A + _FWD_AAAA) == (
        "104.20.23.154",
        "172.66.147.243",
        "2606:4700:10::6814:17fa",
    )


def test_valid_ips_drops_non_ip_literal() -> None:
    # Ein Name (kein IP-Literal) wird verworfen -- defensive Absicherung.
    assert _valid_ips(["example.com.", "104.20.23.154"]) == ("104.20.23.154",)


def test_valid_ips_dedups_stable_order() -> None:
    assert _valid_ips(["1.2.3.4", "1.2.3.4", "5.6.7.8"]) == ("1.2.3.4", "5.6.7.8")


def test_valid_ips_empty_list_is_empty() -> None:
    assert _valid_ips([]) == ()


# ── _query_names: DNSException -> Leer-Zustand, sonst durchgereicht ────────────


def test_query_names_returns_str_list(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ein Answer ist iterierbar ueber seine Rdata; ``str`` liefert den Textnamen.
    monkeypatch.setattr(dns.resolver, "resolve", lambda *_a, **_k: ["one.one.one.one."])
    assert _query_names("1.1.1.1.in-addr.arpa.", "PTR") == ["one.one.one.one."]


@pytest.mark.parametrize(
    "exc_type",
    [
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ],
)
def test_query_names_dns_exception_is_empty(
    monkeypatch: pytest.MonkeyPatch, exc_type: type[dns.exception.DNSException]
) -> None:
    # Jeder DNS-Leerfall (kein Eintrag/keine Antwort/keine Server/Timeout) -> [].
    def _raise(*_a: object, **_k: object) -> list[str]:
        raise exc_type

    monkeypatch.setattr(dns.resolver, "resolve", _raise)
    assert _query_names("nx.invalid", "A") == []


def test_query_names_non_dns_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ein echter Programmierfehler (kein DNSException) wird NICHT verschluckt (S3).
    def _raise(*_a: object, **_k: object) -> list[str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(dns.resolver, "resolve", _raise)
    with pytest.raises(RuntimeError):
        _query_names("example.com", "A")


# ── resolve_ptr (Adapter-Kern, gemocktes _query_names) ────────────────────────


def test_resolve_ptr_hit_returns_name_without_dot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "infrastructure.resolver.dns_ptr_windows._query_names", lambda *_a: _PTR_ONE
    )
    assert asyncio.run(DnspythonPtrResolver().resolve_ptr("1.1.1.1")) == "one.one.one.one"


def test_resolve_ptr_takes_first_of_multiple(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "infrastructure.resolver.dns_ptr_windows._query_names", lambda *_a: _PTR_MULTI
    )
    assert asyncio.run(DnspythonPtrResolver().resolve_ptr("1.1.1.1")) == "first.example.com"


def test_resolve_ptr_no_entry_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Leere Antwort (kein Eintrag/NXDOMAIN -> [] aus _query_names) -> "" (kein Fehler).
    monkeypatch.setattr("infrastructure.resolver.dns_ptr_windows._query_names", lambda *_a: [])
    assert asyncio.run(DnspythonPtrResolver().resolve_ptr("203.0.113.1")) == ""


def test_resolve_ptr_uses_reverse_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # Der Kern bildet aus der ip den reversen Abfragenamen (in-addr.arpa) und fragt PTR.
    captured: list[tuple[object, str]] = []

    def _capture(qname: object, rdtype: str) -> list[str]:
        captured.append((str(qname), rdtype))
        return []

    monkeypatch.setattr("infrastructure.resolver.dns_ptr_windows._query_names", _capture)
    asyncio.run(DnspythonPtrResolver().resolve_ptr("1.1.1.1"))
    assert captured == [("1.1.1.1.in-addr.arpa.", "PTR")]


# ── resolve_forward (Adapter-Kern, gemocktes _query_names) ────────────────────


def test_resolve_forward_combines_a_and_aaaa(monkeypatch: pytest.MonkeyPatch) -> None:
    # Erster Aufruf (A) -> _FWD_A, zweiter Aufruf (AAAA) -> _FWD_AAAA.
    outputs = iter([_FWD_A, _FWD_AAAA])
    monkeypatch.setattr(
        "infrastructure.resolver.dns_ptr_windows._query_names",
        lambda *_a: next(outputs),
    )
    result = asyncio.run(DnspythonPtrResolver().resolve_forward("example.com"))
    assert result == ("104.20.23.154", "172.66.147.243", "2606:4700:10::6814:17fa")


def test_resolve_forward_queries_a_then_aaaa(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reihenfolge/Record-Typen: A vor AAAA, jeweils fuer denselben hostname.
    captured: list[tuple[object, str]] = []

    def _capture(qname: object, rdtype: str) -> list[str]:
        captured.append((qname, rdtype))
        return []

    monkeypatch.setattr("infrastructure.resolver.dns_ptr_windows._query_names", _capture)
    asyncio.run(DnspythonPtrResolver().resolve_forward("example.com"))
    assert captured == [("example.com", "A"), ("example.com", "AAAA")]


def test_resolve_forward_no_hits_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("infrastructure.resolver.dns_ptr_windows._query_names", lambda *_a: [])
    assert asyncio.run(DnspythonPtrResolver().resolve_forward("nx.invalid")) == ()
