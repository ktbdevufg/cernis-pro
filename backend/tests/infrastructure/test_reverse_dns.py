"""Tests des best-effort Reverse-DNS-Adapters (PTR mit hartem Timeout).

Prueft: ein aufloesbarer PTR liefert den Namen ohne Wurzelpunkt; ein Lookup-Fehler
(``socket.herror``/``gaierror``/``OSError``) liefert ``None``; ein leerer Name liefert
``None``; ein haengender Lookup wird durch den Timeout abgeschnitten und liefert ``None``
(kein Blockieren, kein Crash).

``socket.gethostbyaddr`` wird gemockt -- kein echtes Netz noetig (der Laufzeit-Smoke deckt
die echte Aufloesung ab). Die async-Funktion laeuft ueber ``asyncio.run`` (Muster der
uebrigen Worker-Tests im Repo -- kein pytest-asyncio).
"""

import asyncio
import socket
import time

import pytest

from infrastructure.reverse_dns import reverse_dns_name


def test_ptr_liefert_namen_ohne_wurzelpunkt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("dns.google.", [], ["8.8.8.8"]))
    assert asyncio.run(reverse_dns_name("8.8.8.8")) == "dns.google"


def test_ptr_herror_ist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(ip: str) -> tuple[str, list[str], list[str]]:
        raise socket.herror("kein PTR")

    monkeypatch.setattr(socket, "gethostbyaddr", boom)
    assert asyncio.run(reverse_dns_name("203.0.113.7")) is None


def test_ptr_oserror_ist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(ip: str) -> tuple[str, list[str], list[str]]:
        raise OSError("resolver kaputt")

    monkeypatch.setattr(socket, "gethostbyaddr", boom)
    assert asyncio.run(reverse_dns_name("203.0.113.7")) is None


def test_ptr_leerer_name_ist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("", [], ["203.0.113.7"]))
    assert asyncio.run(reverse_dns_name("203.0.113.7")) is None


def test_ptr_timeout_ist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ein haengender Lookup (laenger als der Timeout) darf NICHT blockieren -> None.
    def haengt(ip: str) -> tuple[str, list[str], list[str]]:
        time.sleep(0.5)
        return ("zu.spaet.", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", haengt)
    assert asyncio.run(reverse_dns_name("203.0.113.7", timeout=0.05)) is None
