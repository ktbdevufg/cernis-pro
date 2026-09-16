"""Tests des ResolvePtrBatch-Use-Case gegen einen In-Memory-Fake des PtrResolverPort.

Kein echter Adapter, kein dig, kein Netz -- der Fake erfuellt schlicht das
``PtrResolverPort``-Protocol und zaehlt die ``resolve_ptr``-Aufrufe je IP. Kern der
Behauptungen (Auftrag Paket 5): mehrere IPs (Treffer + "" -> null), Deduplizierung
(gleiche IP zweimal -> Port nur einmal gefragt, aber jede angefragte IP als Schluessel),
TTL-Cache (zweiter Call innerhalb TTL fragt den Port NICHT erneut) und nebenlaeufige
Aufloesung.
"""

import asyncio

from application.resolver import ResolvePtrBatch

# ── In-Memory-Fake des PtrResolverPort ────────────────────────────────────────


class FakePtrResolver:
    """PTR aus einer kontrollierten Map -- kein dig, kein Netz; zaehlt die Aufrufe je IP.

    ``names`` bildet IP -> PTR-Name (fehlt eine IP, liefert der Port ``""`` wie der echte
    Adapter bei "kein Eintrag"). ``calls`` haelt jede aufgeloeste IP fest -- so pruefen die
    Tests Deduplizierung und Cache (welche IP wie oft den Port erreichte).
    """

    def __init__(self, names: dict[str, str] | None = None) -> None:
        self._names = names or {}
        self.calls: list[str] = []

    async def resolve_ptr(self, ip: str) -> str:
        self.calls.append(ip)
        return self._names.get(ip, "")

    async def resolve_forward(self, hostname: str) -> tuple[str, ...]:
        # Vom Batch-Use-Case nicht genutzt -- nur zur Protocol-Erfuellung.
        return ()


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_mehrere_ips_treffer_und_leer_zu_null() -> None:
    """Mehrere IPs: Treffer liefern den Namen, "" wird ehrlich zu None projiziert."""
    uc = ResolvePtrBatch(FakePtrResolver({"1.2.3.4": "host.example.com"}))

    result = asyncio.run(uc(("1.2.3.4", "5.6.7.8")))

    assert result == {"1.2.3.4": "host.example.com", "5.6.7.8": None}


def test_jede_angefragte_ip_erscheint_als_schluessel() -> None:
    """Vollstaendigkeit: JEDE angefragte IP ist ein Schluessel -- auch ohne Treffer."""
    uc = ResolvePtrBatch(FakePtrResolver())

    result = asyncio.run(uc(("1.1.1.1", "8.8.8.8", "9.9.9.9")))

    assert set(result) == {"1.1.1.1", "8.8.8.8", "9.9.9.9"}
    assert all(value is None for value in result.values())


def test_dedupliziert_gleiche_ip_nur_einmal_gefragt() -> None:
    """Gleiche IP zweimal angefragt -> Port nur einmal gerufen, beide Schluessel da."""
    fake = FakePtrResolver({"1.2.3.4": "host.example.com"})
    uc = ResolvePtrBatch(fake)

    result = asyncio.run(uc(("1.2.3.4", "1.2.3.4")))

    # Dedupliziert intern: nur EIN Port-Aufruf fuer die doppelte IP ...
    assert fake.calls == ["1.2.3.4"]
    # ... aber die Map enthaelt den Schluessel (Duplikate kollabieren im dict zu einem).
    assert result == {"1.2.3.4": "host.example.com"}


def test_cache_zweiter_call_fragt_port_nicht_erneut() -> None:
    """Zweiter Call innerhalb der TTL trifft den Cache -> Port wird NICHT erneut gefragt."""
    fake = FakePtrResolver({"1.2.3.4": "host.example.com"})
    uc = ResolvePtrBatch(fake)

    first = asyncio.run(uc(("1.2.3.4",)))
    second = asyncio.run(uc(("1.2.3.4",)))

    assert first == {"1.2.3.4": "host.example.com"}
    assert second == {"1.2.3.4": "host.example.com"}
    # Nur EIN Port-Aufruf insgesamt -- der zweite Call kam aus dem Cache.
    assert fake.calls == ["1.2.3.4"]


def test_cache_mischung_nur_neue_ip_aufloesen() -> None:
    """Zweiter Call mit einer alten + einer neuen IP -> nur die neue erreicht den Port."""
    fake = FakePtrResolver({"1.2.3.4": "a.example.com", "5.6.7.8": "b.example.com"})
    uc = ResolvePtrBatch(fake)

    asyncio.run(uc(("1.2.3.4",)))
    result = asyncio.run(uc(("1.2.3.4", "5.6.7.8")))

    assert result == {"1.2.3.4": "a.example.com", "5.6.7.8": "b.example.com"}
    # 1.2.3.4 kam aus dem Cache; nur 5.6.7.8 erreichte den Port ein zweites Mal.
    assert fake.calls == ["1.2.3.4", "5.6.7.8"]


def test_cache_ablauf_nach_ttl_fragt_erneut(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Nach Ablauf der TTL (monotone Uhr vorgespult) wird der Port erneut gefragt."""
    from application.resolver.use_cases import _PTR_CACHE_TTL_SECS

    fake = FakePtrResolver({"1.2.3.4": "host.example.com"})
    uc = ResolvePtrBatch(fake)

    clock = {"now": 1000.0}
    # Die im Use-Case-Modul gebundene ``time.monotonic`` patchen (String-Target, damit der
    # Modul-Namespace nicht direkt als Attribut angefasst wird) -> kontrollierbare Uhr.
    monkeypatch.setattr("application.resolver.use_cases.time.monotonic", lambda: clock["now"])

    asyncio.run(uc(("1.2.3.4",)))
    # Uhr ueber die TTL hinaus vorspulen -> der Cache-Eintrag ist abgelaufen.
    clock["now"] += _PTR_CACHE_TTL_SECS + 1.0
    asyncio.run(uc(("1.2.3.4",)))

    assert fake.calls == ["1.2.3.4", "1.2.3.4"]  # zweimal gefragt (Cache abgelaufen)


def test_nebenlaeufige_aufloesung() -> None:
    """Die eindeutigen IPs werden NEBENLAEUFIG aufgeloest (gather), nicht seriell.

    Ein Fake mit einem kurzen ``sleep`` je Aufruf: laeuft der Use-Case nebenlaeufig, ist
    die Gesamtzeit ~ein sleep, nicht die Summe ueber alle IPs. Wir pruefen das Verhalten
    ueber die Reihenfolge der Fertigstellung statt ueber eine fragile Zeitmessung: ein
    Barrier (Event), das alle gestarteten Coroutinen freigibt, kann nur aufgehen, wenn
    sie GLEICHZEITIG laufen -- bei serieller Ausfuehrung gaebe es einen Deadlock.
    """
    started = 0
    gate = asyncio.Event()

    class BarrierPtrResolver:
        async def resolve_ptr(self, ip: str) -> str:
            nonlocal started
            started += 1
            if started == 3:
                gate.set()  # alle drei sind gestartet -> freigeben
            await gate.wait()  # blockiert, bis alle drei laufen (nur nebenlaeufig moeglich)
            return f"host-{ip}"

        async def resolve_forward(self, hostname: str) -> tuple[str, ...]:
            return ()

    uc = ResolvePtrBatch(BarrierPtrResolver())

    async def _run() -> dict[str, str | None]:
        return await asyncio.wait_for(uc(("1.1.1.1", "2.2.2.2", "3.3.3.3")), timeout=2.0)

    result = asyncio.run(_run())

    assert result == {
        "1.1.1.1": "host-1.1.1.1",
        "2.2.2.2": "host-2.2.2.2",
        "3.3.3.3": "host-3.3.3.3",
    }
