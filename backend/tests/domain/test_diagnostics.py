"""Unit-Tests der diagnostics-Domaene -- reine Wertobjekte + ``dedup_records``.

Prueft die frozen-Semantik der Wertobjekte, die ehrliche None-Naht des nicht-antwortenden
traceroute-Hops und die leere DNS-Antwort, sowie die reine Funktion ``dedup_records``
(Dedup ueber (Typ, Wert), deterministische Sortierung). Alle Werte kommen als Felder
herein -> rein deterministisch, kein I/O, keine Uhr.
"""

import pytest

from domain.diagnostics import (
    DnsRecord,
    DnsResult,
    TracerouteHop,
    TracerouteResult,
    dedup_records,
)

# ── Wertobjekte (frozen + ehrliche None-Naht) ─────────────────────────────────


def test_dns_record_is_frozen() -> None:
    rec = DnsRecord(record_type="A", value="1.2.3.4")
    with pytest.raises(AttributeError):
        rec.value = "9.9.9.9"  # type: ignore[misc]


def test_dns_result_empty_records_is_not_an_error() -> None:
    # Leere records = keine Antwort (NXDOMAIN/kein Eintrag), KEIN Fehler.
    result = DnsResult(query="nope.invalid", requested_types=("A",), records=())
    assert result.records == ()
    assert result.requested_types == ("A",)


def test_traceroute_hop_non_responding_is_honest_none() -> None:
    # Ein nicht-antwortender Hop (Timeout/``*``) -> address/rtt_ms ehrlich None.
    hop = TracerouteHop(hop=7, address=None, rtt_ms=None)
    assert hop.hop == 7
    assert hop.address is None
    assert hop.rtt_ms is None


def test_traceroute_hop_is_frozen() -> None:
    hop = TracerouteHop(hop=1, address="1.2.3.4", rtt_ms=0.5)
    with pytest.raises(AttributeError):
        hop.rtt_ms = 1.0  # type: ignore[misc]


def test_traceroute_result_carries_privileged_flag() -> None:
    # privileged spiegelt ehrlich, WIE gemessen wurde.
    result = TracerouteResult(target="example.com", privileged=True, hops=())
    assert result.privileged is True
    assert result.target == "example.com"
    assert result.hops == ()


# ── dedup_records (rein, deterministisch, mutationsprobe-tauglich) ─────────────


def test_dedup_records_empty() -> None:
    assert dedup_records([]) == ()


def test_dedup_records_removes_duplicate_type_value_pairs() -> None:
    # Zweimal derselbe (Typ, Wert) -> nur EIN Eintrag.
    records = [
        DnsRecord(record_type="A", value="1.2.3.4"),
        DnsRecord(record_type="A", value="1.2.3.4"),
    ]
    assert dedup_records(records) == (DnsRecord(record_type="A", value="1.2.3.4"),)


def test_dedup_records_keeps_same_value_different_type() -> None:
    # Gleicher Wert, anderer Typ -> KEIN Duplikat (beide bleiben).
    records = [
        DnsRecord(record_type="A", value="1.2.3.4"),
        DnsRecord(record_type="PTR", value="1.2.3.4"),
    ]
    result = dedup_records(records)
    assert len(result) == 2


def test_dedup_records_sorts_deterministically() -> None:
    # Eingangsreihenfolge bewusst durcheinander; Ergebnis aufsteigend nach (Typ, Wert).
    records = [
        DnsRecord(record_type="A", value="9.9.9.9"),
        DnsRecord(record_type="AAAA", value="::1"),
        DnsRecord(record_type="A", value="1.1.1.1"),
    ]
    result = dedup_records(records)
    assert result == (
        DnsRecord(record_type="A", value="1.1.1.1"),
        DnsRecord(record_type="A", value="9.9.9.9"),
        DnsRecord(record_type="AAAA", value="::1"),
    )


def test_dedup_records_first_occurrence_wins_identity() -> None:
    # Bei Duplikat gewinnt das erste Vorkommen die Identitaet (hier wertgleich, aber
    # belegt, dass kein zweiter Eintrag durchrutscht -- Mutationsprobe gegen ">= statt >").
    records = [
        DnsRecord(record_type="MX", value="10 a.example."),
        DnsRecord(record_type="MX", value="10 a.example."),
        DnsRecord(record_type="MX", value="20 b.example."),
    ]
    result = dedup_records(records)
    assert result == (
        DnsRecord(record_type="MX", value="10 a.example."),
        DnsRecord(record_type="MX", value="20 b.example."),
    )
