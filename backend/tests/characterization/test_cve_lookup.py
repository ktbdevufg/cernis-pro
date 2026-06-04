"""Characterization-Contract des CVE-Lookup-Altcode (``modules/cve.py``).

Friert den Ist-Zustand VOR der SEC.4-Heilung ein (Strangler-Fig). Der EINZIGE Netz-Call
ist ``urllib.request.urlopen`` in ``_fetch_cves`` (cve.py:80) -- der wird gemockt, es
passiert NIE ein echter NVD-Request. ``time.sleep`` (cve.py:116, NVD-Rate-Limit 0.6s)
wird ebenfalls gemockt, damit die Tests schnell sind.

────────────────────────────────────────────────────────────────────────────
EINGEFRORENE AS-IS-VERHALTEN
────────────────────────────────────────────────────────────────────────────

ERFOLGSFALL (Parse-Vertrag):
  * ``_fetch_cves`` liest die NVD-2.0-JSON-Struktur:
    ``{"vulnerabilities": [{"cve": {"id", "descriptions":[{lang,value}],
       "metrics": {"cvssMetricV31":[{"cvssData":{"baseScore","baseSeverity"}}]},
       "published"}}]}``.
  * ``_parse_severity`` liest cvssMetricV31 > V30 > V2 (erste vorhandene), zieht
    ``baseScore``/``baseSeverity`` (uppercased).
  * ``lookup_cves_for_host`` sortiert CRITICAL<HIGH<MEDIUM<LOW<UNKNOWN, dann -cvss;
    dedupliziert Ports (``checked``-Set); priorisiert "interessante" Ports zuerst.

S3-FALLBACKS (AS-IS eingefroren -- SEC.4 heilt sie zu explizitem Fehler):
  * E.2 (cve.py:82-83): ``_fetch_cves`` faengt JEDE Exception (Netz/Timeout/JSON) und
    gibt ``{}`` zurueck -> ``lookup_*`` liefert ``[]``. KEIN Log. Nicht unterscheidbar
    von "NVD kennt 0 Treffer". >> AS-IS, S3-Fallback -- SEC.4 macht daraus einen
    expliziten Fehler (NVD-down != 0-Treffer).
  * E.3 (cve.py:98-99): ``_parse_severity`` faengt jede Exception beim Score-Parse und
    faellt still auf ``("UNKNOWN", 0.0)`` zurueck. >> AS-IS, S3-Fallback.
"""

import json
from typing import Any

import pytest


@pytest.fixture
def cve(monkeypatch: pytest.MonkeyPatch) -> Any:
    """cve-Modul mit gemocktem time.sleep (Rate-Limit) -- kein echtes Warten."""
    from modules import cve as cve_mod

    monkeypatch.setattr(cve_mod.time, "sleep", lambda _s: None)
    return cve_mod


class _FakeResponse:
    """Context-Manager wie urlopen-Rueckgabe; .read() liefert JSON-Bytes."""

    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, cve: Any, payload: Any) -> None:
    """Mockt die EINE Netz-Stelle (urllib.request.urlopen) auf eine feste NVD-Antwort."""
    monkeypatch.setattr(
        cve.urllib.request, "urlopen", lambda _req, timeout=10: _FakeResponse(payload)
    )


def _nvd_payload(
    cve_id: str, desc: str, score: float, severity: str, published: str = "2023-01-15T00:00:00"
) -> dict[str, Any]:
    """Realistische NVD-2.0-Struktur mit cvssMetricV31."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {"lang": "de", "value": "ignoriert"},
                        {"lang": "en", "value": desc},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "baseSeverity": severity}}
                        ]
                    },
                    "published": published,
                }
            }
        ]
    }


# ── _fetch_cves: I/O-Kern + E.2-Fallback ──────────────────────


def test_fetch_cves_success_returns_parsed_json(cve: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _nvd_payload("CVE-2023-0001", "test", 9.8, "CRITICAL")
    _patch_urlopen(monkeypatch, cve, payload)
    data = cve._fetch_cves("openssh")
    assert data == payload  # roh durchgereicht


def test_fetch_cves_network_error_returns_empty_dict_no_log(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.2 AS-IS: urlopen wirft -> _fetch_cves verschluckt -> {} (kein Log).
    # SEC.4 heilt das zu explizitem Fehler.
    def _boom(_req: Any, timeout: int = 10) -> Any:
        raise OSError("NVD unreachable")

    monkeypatch.setattr(cve.urllib.request, "urlopen", _boom)
    assert cve._fetch_cves("openssh") == {}  # S3-Fallback: leeres dict, ununterscheidbar


def test_E2_network_error_and_zero_results_are_indistinguishable(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.2 KERN-VERTRAG (Vorher-Referenz fuer SEC.4): der Netzfehler-Fall und der
    # echte "NVD kennt 0 Treffer"-Fall liefern bei lookup_cves_for_port BEIDE ``[]`` --
    # im Ergebnis NICHT unterscheidbar. GENAU DAS heilt SEC.4 (Fehler -> Exception,
    # 0-Treffer -> weiterhin []). Hier wird die Ununterscheidbarkeit als ASSERT gefasst,
    # nicht nur als Kommentar -- sonst fehlte der Beweis, WAS die Heilung aendert.

    # (1) Netzfehler: urlopen wirft.
    def _boom(_req: Any, timeout: int = 10) -> Any:
        raise OSError("NVD unreachable")

    monkeypatch.setattr(cve.urllib.request, "urlopen", _boom)
    result_on_error = cve.lookup_cves_for_port(22, service="ssh")

    # (2) Echte 0 Treffer: NVD antwortet sauber mit leerer vulnerabilities-Liste.
    monkeypatch.setattr(
        cve.urllib.request,
        "urlopen",
        lambda _req, timeout=10: _FakeResponse({"vulnerabilities": []}),
    )
    result_on_zero = cve.lookup_cves_for_port(22, service="ssh")

    # Der Kern: beide Wege liefern dasselbe [] -- ununterscheidbar.
    assert result_on_error == []
    assert result_on_zero == []
    assert result_on_error == result_on_zero


# ── _parse_severity: Erfolgsfall + E.3-Fallback ───────────────


def test_parse_severity_reads_cvss_v31(cve: Any) -> None:
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "high"}}]}
    sev, score = cve._parse_severity(metrics)
    assert sev == "HIGH"  # uppercased
    assert score == 7.5


def test_parse_severity_prefers_v31_over_v30_over_v2(cve: Any) -> None:
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
    }
    sev, score = cve._parse_severity(metrics)
    assert (sev, score) == ("CRITICAL", 9.0)  # V31 zuerst


def test_parse_severity_missing_metrics_returns_unknown(cve: Any) -> None:
    # Keine bekannte cvss-Version -> ("UNKNOWN", 0.0).
    assert cve._parse_severity({}) == ("UNKNOWN", 0.0)


def test_parse_severity_broken_metric_falls_back_unknown(cve: Any) -> None:
    # E.3 AS-IS: cvssData fehlt -> innerer except -> still ("UNKNOWN", 0.0).
    # SEC.4 entscheidet, ob das ein Fehler sein soll.
    metrics: dict[str, Any] = {"cvssMetricV31": [{"NOT_cvssData": {}}]}
    assert cve._parse_severity(metrics) == ("UNKNOWN", 0.0)


# ── lookup_cves_for_port: Parse-Vertrag + leere Faelle ────────


def test_lookup_cves_for_port_parses_entry(cve: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _nvd_payload(
        "CVE-2023-1234", "OpenSSH flaw", 7.5, "HIGH", published="2023-03-20T12:00:00"
    )
    _patch_urlopen(monkeypatch, cve, payload)
    results = cve.lookup_cves_for_port(22, service="ssh", max_results=3)
    assert len(results) == 1
    r = results[0]
    assert r.cve_id == "CVE-2023-1234"
    assert r.description == "OpenSSH flaw"  # englische desc gewaehlt
    assert r.severity == "HIGH"
    assert r.cvss_score == 7.5
    assert r.port == 22
    assert r.service == "ssh"
    assert r.published == "2023-03-20"  # [:10] abgeschnitten
    assert r.url == "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"


def test_lookup_cves_for_port_unknown_port_no_keywords_returns_empty(cve: Any) -> None:
    # Port ohne PORT_TO_KEYWORDS-Eintrag + kein brauchbarer service -> [] (kein Netz-Call).
    assert cve.lookup_cves_for_port(65000, service="") == []


def test_lookup_cves_for_port_network_error_returns_empty(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # E.2 durchgereicht: urlopen wirft -> _fetch_cves={} -> "vulnerabilities" fehlt -> [].
    def _boom(_req: Any, timeout: int = 10) -> Any:
        raise TimeoutError

    monkeypatch.setattr(cve.urllib.request, "urlopen", _boom)
    assert cve.lookup_cves_for_port(22, service="ssh") == []


# ── lookup_cves_for_host: Sortierung + Dedup ──────────────────


def test_lookup_cves_for_host_sorts_by_severity_then_cvss(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Je Port eine andere Antwort -> _fetch_cves haengt am keyword.
    # AS-IS keyword-Bildung (cve.py:108-115): keyword = keywords[0].
    #  * Port 22, service="ssh" (len==3, NICHT >3) -> service ignoriert ->
    #    keyword = PORT_TO_KEYWORDS[22][0] = "openssh".
    #  * Port 3306, service="mysql" (len==5 >3) -> svc_words=["mysql"] vorangestellt ->
    #    keyword = "mysql".
    responses = {
        "openssh": _nvd_payload("CVE-LOW", "low", 3.1, "LOW"),
        "mysql": _nvd_payload("CVE-CRIT", "crit", 9.9, "CRITICAL"),
    }

    def _fake(keyword: str, results_per_page: int = 5) -> dict[str, Any]:
        return responses.get(keyword, {})

    monkeypatch.setattr(cve, "_fetch_cves", _fake)
    ports = [{"port": 22, "service": "ssh"}, {"port": 3306, "service": "mysql"}]
    results = cve.lookup_cves_for_host(ports)
    # CRITICAL vor LOW (Vertrag: sev_order CRITICAL<...<UNKNOWN).
    assert [r.severity for r in results] == ["CRITICAL", "LOW"]


def test_keyword_uses_port_table_when_service_too_short(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AS-IS-Vertrag: service mit len<=3 wird NICHT als keyword genutzt (cve.py:108).
    # service="ssh" (3 Zeichen) -> keyword bleibt PORT_TO_KEYWORDS[22][0]="openssh".
    seen: list[str] = []

    def _fake(keyword: str, results_per_page: int = 5) -> dict[str, Any]:
        seen.append(keyword)
        return {}

    monkeypatch.setattr(cve, "_fetch_cves", _fake)
    cve.lookup_cves_for_port(22, service="ssh")
    assert seen == ["openssh"]


def test_keyword_prepends_service_when_long_enough(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Gegenprobe: service mit len>3 wird vorangestellt -> keyword = erstes service-Wort.
    seen: list[str] = []

    def _fake(keyword: str, results_per_page: int = 5) -> dict[str, Any]:
        seen.append(keyword)
        return {}

    monkeypatch.setattr(cve, "_fetch_cves", _fake)
    cve.lookup_cves_for_port(3306, service="mysql server")
    assert seen == ["mysql"]  # split()[:2][0]


def test_lookup_cves_for_host_dedups_repeated_ports(
    cve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    def _fake_port(port: int, service: str = "", max_results: int = 3) -> list[Any]:
        calls.append(port)
        return []

    monkeypatch.setattr(cve, "lookup_cves_for_port", _fake_port)
    # Port 22 doppelt -> nur EIN Lookup (checked-Set).
    cve.lookup_cves_for_host([{"port": 22}, {"port": 22}, {"port": 80}])
    assert calls.count(22) == 1
    assert 80 in calls
