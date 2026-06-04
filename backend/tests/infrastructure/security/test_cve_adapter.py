"""Tests fuer ``CveLookupAdapter`` (SEC.4) -- v2-Reimplementierung + S3-Heilung E.2/E.3.

AUFLAGE A2: jede Heilung als VERTRAG gegen die SEC.1b-Vorher-Referenz:
  * Fehler-Fall LOGGT jetzt (assert auf das Warn-Event) UND das Ergebnis ist wie
    SEC.1b-Vorher ([]/UNKNOWN) -- die Heilung aendert das ERGEBNIS nicht, nur die
    SICHTBARKEIT (Log).
  * Loop ueberlebt: ein Port wirft, einer liefert -> der gesunde kommt durch.

Log-Capture via ``structlog.testing.capture_logs`` (fängt Events als dicts). Netz-I/O
gemockt (``urllib.request.urlopen`` + ``time.sleep``) -- kein echter NVD-Call.
"""

import json
import time
import urllib.request
from typing import Any

import pytest
from structlog.testing import capture_logs

from infrastructure.security import cve as cve_mod
from ports.security import CveFinding, PortQuery


class _FakeResponse:
    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _nvd(cve_id: str, score: float, severity: str) -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "desc"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "baseSeverity": severity}}
                        ]
                    },
                    "published": "2023-01-15T00:00:00",
                }
            }
        ]
    }


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)


# ── E.2: NVD-Fehler -> [] + Warn-Log (vorher still) ───────────


def test_E2_fetch_error_returns_empty_AND_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_req: Any, timeout: int = 10) -> Any:
        raise OSError("NVD unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    with capture_logs() as logs:
        result = cve_mod._fetch_cves("openssh", results_per_page=3)

    # Ergebnis wie SEC.1b-Vorher: leeres dict (-> spaeter []).
    assert result == {}
    # HEILUNG: jetzt geloggt (vorher kein Log).
    assert any(e["event"] == "nvd_fetch_failed" for e in logs)


def test_E2_zero_results_does_NOT_log(monkeypatch: pytest.MonkeyPatch) -> None:
    # Gegenpol: echte 0 Treffer (NVD antwortet sauber leer) -> KEIN Warn-Log.
    # Das ist die Ununterscheidbarkeits-Heilung: nur der FEHLER loggt, nicht das Negativ.
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _req, timeout=10: _FakeResponse({"vulnerabilities": []}),
    )
    with capture_logs() as logs:
        result = cve_mod._fetch_cves("openssh", results_per_page=3)
    assert result == {"vulnerabilities": []}
    assert not any(e["event"] == "nvd_fetch_failed" for e in logs)


# ── E.3: kaputte metrics -> UNKNOWN + Warn-Log ────────────────


def test_E3_broken_severity_returns_unknown_AND_logs() -> None:
    # baseScore nicht in float konvertierbar -> float(...) wirft im try (Altcode-treuer
    # Crash-Pfad) -> Fallback ("UNKNOWN", 0.0). Genau dieser except wird geheilt (geloggt).
    metrics: dict[str, Any] = {
        "cvssMetricV31": [{"cvssData": {"baseScore": "not-a-number", "baseSeverity": "HIGH"}}]
    }
    with capture_logs() as logs:
        sev, score = cve_mod._parse_severity(metrics)
    # Ergebnis wie SEC.1b-Vorher.
    assert (sev, score) == ("UNKNOWN", 0.0)
    # HEILUNG: geloggt.
    assert any(e["event"] == "cve_severity_parse_failed" for e in logs)


def test_E3_valid_severity_does_NOT_log() -> None:
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    with capture_logs() as logs:
        sev, score = cve_mod._parse_severity(metrics)
    assert (sev, score) == ("HIGH", 7.5)
    assert not any(e["event"] == "cve_severity_parse_failed" for e in logs)


# ── Loop ueberlebt: ein Port wirft, einer liefert ────────────


def test_loop_survives_one_failing_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # _lookup_for_port WIRFT fuer Port 22 mitten im Loop (unerwarteter Fehler ausserhalb
    # der inneren _fetch_cves-Faenge) -> der per-Item-try IN der Schleife faengt es,
    # Port 3306 wird weiter verarbeitet. Das beweist den Loop-Schutz an der richtigen
    # Stelle (try IN der Schleife, nicht drumherum).
    from infrastructure.security import cve as cve_module

    def _fake_port(port: int, service: str = "", max_results: int = 3) -> list[Any]:
        if port == 22:
            raise RuntimeError("unexpected lookup error")  # wirft MITTEN im Loop
        return [
            CveFinding(
                cve_id="CVE-MYSQL",
                description="d",
                severity="CRITICAL",
                cvss_score=9.0,
                published="2023",
                port=port,
            )
        ]

    monkeypatch.setattr(cve_module, "_lookup_for_port", _fake_port)

    with capture_logs() as logs:
        result = cve_mod.CveLookupAdapter()._lookup_for_host_sync(
            [PortQuery(22, "ssh"), PortQuery(3306, "mysql")]
        )

    # (a) der GESUNDE Port-Treffer ist konkret drin.
    assert [f.cve_id for f in result] == ["CVE-MYSQL"]
    # (b) der KAPUTTE ist geloggt + fehlt im Ergebnis.
    assert any(e["event"] == "cve_port_lookup_failed" and e["port"] == 22 for e in logs)
    assert all(f.port != 22 for f in result)


# MUTATIONSPROBE (dokumentiert): zieht man in cve.py:_lookup_for_host_sync das
# per-Item-try VOR/UM die ``for p``-Schleife (statt drin), killt der RuntimeError bei
# Port 22 die ganze Schleife -> CVE-MYSQL fehlt -> dieser Test wird rot.


def test_lookup_sorts_by_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    def _urlopen(req: Any, timeout: int = 10) -> Any:
        if "openssh" in req.full_url:
            return _FakeResponse(_nvd("CVE-LOW", 3.0, "LOW"))
        return _FakeResponse(_nvd("CVE-CRIT", 9.5, "CRITICAL"))

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    result = cve_mod.CveLookupAdapter()._lookup_for_host_sync(
        [PortQuery(22, "ssh"), PortQuery(3306, "mysql")]
    )
    assert [f.severity for f in result] == ["CRITICAL", "LOW"]


# ── MUTATIONSPROBE Loggen (dokumentiert): das Warn entfernen ──
#
# Entfernt man in cve.py:_fetch_cves das ``_logger.warning("nvd_fetch_failed", ...)``,
# wird test_E2_fetch_error_returns_empty_AND_logs rot (das "loggt jetzt"-Assert
# schlaegt fehl) -- der Ergebnis-Teil (== {}) bliebe gruen. Das beweist, dass der Test
# die SICHTBARKEITS-Heilung faengt, nicht nur das (unveraenderte) Ergebnis.


def test_no_keywords_returns_empty_without_call(monkeypatch: pytest.MonkeyPatch) -> None:
    # Port ohne keyword + kein brauchbarer service -> [] ohne urlopen-Aufruf.
    def _urlopen(_req: Any, timeout: int = 10) -> Any:
        raise AssertionError("should not be called")

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    result = cve_mod.CveLookupAdapter()._lookup_for_host_sync([PortQuery(65000, "")])
    assert result == []
