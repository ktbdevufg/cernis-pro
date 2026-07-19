"""Strukturtest des ``CaptureAccessPort`` (Etappe 2): Fakes + Adapter erfuellen ihn.

Muster ``test_analysis_ports.py``: der reine ``typing.Protocol``-Vertrag hat kein
Verhalten, geprueft wird die strukturelle Konformitaet.

* **statisch (mypy):** ``_assert_capture_access`` nimmt den Port-TYP und bekommt die
  Instanzen uebergeben. Passt eine Signatur nicht, schlaegt ``uv run mypy`` fehl --
  das ist die eigentliche Pruefung.
* **dynamisch (pytest):** ein Smoke ruft beide Methoden auf und prueft die Domaenen-
  Rueckgaben.

Geprueft werden BEIDE realen Adapter (macOS + uebrige Plattformen), damit die
Plattform-Weiche in ``app.py`` in jedem Zweig einen vertragstreuen Adapter bindet.
Der macOS-Adapter wird dabei NUR strukturell geprueft (keine Ausfuehrung) -- sein
Verhalten deckt ``tests/infrastructure/test_capture_access_macos.py`` plattformfrei ab.

KEIN ``@runtime_checkable`` am Port -> bewusst KEIN ``isinstance``-Check; die
Konformitaet traegt mypy, nicht die Laufzeit.
"""

from domain.capture_access import (
    CaptureAccessOutcome,
    CaptureAccessResult,
    CaptureAccessState,
    CaptureAccessStatus,
)
from infrastructure.capture_access_macos import CaptureAccessAdapter as MacosAdapter
from infrastructure.capture_access_other import CaptureAccessAdapter as OtherAdapter
from ports.capture_access import CaptureAccessPort

# ── Fake: minimale, vertragstreue Implementierung ───────────────────────────


class _FakeCaptureAccess:
    def status(self) -> CaptureAccessStatus:
        return CaptureAccessStatus(state=CaptureAccessState.GRANTED)

    def grant(self) -> CaptureAccessResult:
        return CaptureAccessResult(outcome=CaptureAccessOutcome.GRANTED)


# ── Statische Konformitaet: mypy prueft die Zuweisung an den Port-Typ ───────


def _assert_capture_access(_: CaptureAccessPort) -> None: ...


def test_fake_satisfies_port_statically() -> None:
    """mypy-Beweis: der Fake genuegt dem ``CaptureAccessPort``."""
    _assert_capture_access(_FakeCaptureAccess())


def test_both_platform_adapters_satisfy_port_statically() -> None:
    """mypy-Beweis: BEIDE Zweige der Plattform-Weiche erfuellen denselben Port.

    Nur Konstruktion + Typzuweisung, KEIN Methodenaufruf -- der macOS-Adapter wuerde
    sonst je nach Testmaschine echte Geraeteproben ausloesen.
    """
    _assert_capture_access(MacosAdapter())
    _assert_capture_access(OtherAdapter())


# ── Dynamischer Smoke ───────────────────────────────────────────────────────


def test_fake_returns_domain_values() -> None:
    """Beide Operationen liefern Domaenenwerte (kein dict, keine Wire-Form)."""
    fake = _FakeCaptureAccess()
    status = fake.status()
    result = fake.grant()

    assert isinstance(status, CaptureAccessStatus)
    assert status.state is CaptureAccessState.GRANTED
    assert status.detail == ""  # Erfolg braucht keine Begruendung

    assert isinstance(result, CaptureAccessResult)
    assert result.outcome is CaptureAccessOutcome.GRANTED
    assert result.reason == ""


def test_outcome_distinguishes_cancel_from_failure() -> None:
    """Abbruch und Fehlschlag sind VERSCHIEDENE Werte -- die S3-Kernunterscheidung.

    Faellt diese Trennung je zusammen (z. B. weil jemand Abbruch als Fehler
    modelliert), schlaegt dieser Test fehl -- genau das soll er verhindern.
    """
    werte = [str(outcome) for outcome in CaptureAccessOutcome]

    # Vier Ausgaenge, vier VERSCHIEDENE Wire-Werte -- faellt je einer mit einem
    # anderen zusammen, kann das Frontend sie nicht mehr auseinanderhalten.
    assert len(set(werte)) == len(werte)
    assert set(werte) == {"granted", "cancelled", "failed", "not_applicable"}
