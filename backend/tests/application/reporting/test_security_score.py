"""Tests fuer die reine Netz-Gesundheit-Score-Rechnung (Sicherheitsbericht, Etappe 1).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router, KEINE Domaenen-
Importe. Die Geraete-Lasten kommen bereits verdichtet als DeviceBurden herein
(worst_severity je Geraet vom Aufrufer bestimmt) -- so bleibt die Rechnung voll
deterministisch pruefbar.

Abgedeckt: leere Eingabe; nur saubere Geraete; ein kritisches unter vielen
sauberen; Mischfall critical+notable (Last und Score exakt nachgerechnet); die
Level-Grenzen (genau 80/79, genau 50/49); Relativitaet (kleines vs grosses Netz
bei gleicher absoluter Last); abweichende Gewichte/Schwellen als Parameter;
Clamping auf [0, 100] bei sehr hoher Last.
"""

from __future__ import annotations

from application.reporting.security_score import (
    DeviceBurden,
    SecurityScore,
    compute_security_score,
)


def _burden(severity: str, label: str = "dev") -> DeviceBurden:
    """Geraete-Last (Test-Helfer)."""
    return DeviceBurden(device_label=label, worst_severity=severity)


def _devices(critical: int = 0, notable: int = 0, clean: int = 0) -> list[DeviceBurden]:
    """Liste aus n critical + m notable + k sauberen Geraeten (Test-Helfer)."""
    return (
        [_burden("critical", f"c{i}") for i in range(critical)]
        + [_burden("notable", f"n{i}") for i in range(notable)]
        + [_burden("none", f"s{i}") for i in range(clean)]
    )


# ── Leere Eingabe ───────────────────────────────────────────────────────────


def test_leere_eingabe_score_100_level_gut_zaehler_null() -> None:
    result = compute_security_score([])

    assert result == SecurityScore(
        score=100,
        level="gut",
        device_count=0,
        total_burden=0.0,
        critical_devices=0,
        notable_devices=0,
        clean_devices=0,
    )


# ── Nur saubere Geraete ─────────────────────────────────────────────────────


def test_nur_saubere_geraete_score_100() -> None:
    result = compute_security_score(_devices(clean=10))

    assert result.score == 100
    assert result.level == "gut"
    assert result.total_burden == 0.0
    assert result.device_count == 10
    assert result.clean_devices == 10
    assert result.critical_devices == 0
    assert result.notable_devices == 0


# ── Ein kritisches unter vielen sauberen ────────────────────────────────────


def test_ein_kritisches_unter_24_score_96() -> None:
    # round(100 * (1 - 1/24)) = round(95.833...) = 96
    result = compute_security_score(_devices(critical=1, clean=23))

    assert result.device_count == 24
    assert result.total_burden == 1.0
    assert result.score == 96
    assert result.level == "gut"
    assert result.critical_devices == 1
    assert result.clean_devices == 23


# ── Mischfall critical + notable (Last und Score exakt nachgerechnet) ────────


def test_mischfall_2_critical_2_notable_unter_24_score_89() -> None:
    # Last = 2 * 1.0 + 2 * 0.3334 = 2.6668
    # round(100 * (1 - 2.6668/24)) = round(88.8883...) = 89
    result = compute_security_score(_devices(critical=2, notable=2, clean=20))

    assert result.device_count == 24
    assert result.total_burden == 2.6668
    assert result.score == 89
    assert result.level == "gut"
    assert result.critical_devices == 2
    assert result.notable_devices == 2
    assert result.clean_devices == 20


# ── Level-Grenzen ───────────────────────────────────────────────────────────


def test_level_grenze_genau_80_ist_gut() -> None:
    # N=5, 1 critical -> 1 - 1/5 = 0.80 -> score 80
    result = compute_security_score(_devices(critical=1, clean=4))

    assert result.score == 80
    assert result.level == "gut"


def test_level_grenze_79_ist_maessig() -> None:
    # N=100, 21 critical -> 1 - 21/100 = 0.79 -> score 79
    result = compute_security_score(_devices(critical=21, clean=79))

    assert result.score == 79
    assert result.level == "maessig"


def test_level_grenze_genau_50_ist_maessig() -> None:
    # N=2, 1 critical -> 1 - 1/2 = 0.50 -> score 50
    result = compute_security_score(_devices(critical=1, clean=1))

    assert result.score == 50
    assert result.level == "maessig"


def test_level_grenze_49_ist_kritisch() -> None:
    # N=100, 51 critical -> 1 - 51/100 = 0.49 -> score 49
    result = compute_security_score(_devices(critical=51, clean=49))

    assert result.score == 49
    assert result.level == "kritisch"


# ── Relativitaet: kleines vs grosses Netz, gleiche absolute Last ─────────────


def test_relativitaet_kleines_vs_grosses_netz_gleiche_last() -> None:
    # Gleiche absolute Last (genau 1 critical), unterschiedliche Netzgroesse.
    klein = compute_security_score(_devices(critical=1, clean=3))  # N=4 -> 75
    gross = compute_security_score(_devices(critical=1, clean=23))  # N=24 -> 96

    assert klein.total_burden == gross.total_burden == 1.0
    assert klein.score == 75
    assert gross.score == 96
    assert klein.score < gross.score


# ── Abweichende Gewichte/Schwellen als Parameter ────────────────────────────


def test_abweichende_gewichte_wirken() -> None:
    # notable_weight auf 1.0 hochgezogen: 4 notable unter 10 -> Last 4.0 -> score 60
    result = compute_security_score(_devices(notable=4, clean=6), notable_weight=1.0)

    assert result.total_burden == 4.0
    assert result.score == 60


def test_abweichende_schwellen_wirken() -> None:
    # Score 60 (4 notable unter 10, notable_weight 1.0): mit angehobenen Schwellen
    # (good>=70, mid>=55) faellt 60 in "maessig"; mit den Defaults waere es "gut".
    devices = _devices(notable=4, clean=6)

    default = compute_security_score(devices, notable_weight=1.0)
    streng = compute_security_score(
        devices, notable_weight=1.0, level_good_min=70, level_mid_min=55
    )

    assert default.score == streng.score == 60
    assert default.level == "maessig"  # 60 < 80, >= 50
    assert streng.level == "maessig"  # 60 < 70, >= 55


# ── Clamping: sehr hohe Last -> score 0, nie negativ ────────────────────────


def test_clamping_last_gleich_n_score_0() -> None:
    # Last genau gleich N (jedes Geraet critical, Gewicht 1.0): 1 - N/N = 0 -> score 0.
    result = compute_security_score(_devices(critical=3))

    assert result.device_count == 3
    assert result.total_burden == 3.0
    assert result.score == 0
    assert result.level == "kritisch"


def test_clamping_negativer_rohwert_wird_0() -> None:
    # Last GROESSER als N erzeugt einen negativen Rohwert, der auf 0 geclamped
    # werden muss (Score nie negativ). Mit critical_weight=5.0 traegt ein einziges
    # critical-Geraet Last 5.0: 1 critical unter 2 -> 1 - 5/2 = -1.5 -> round(-150)
    # -> clamp 0.
    result = compute_security_score(_devices(critical=1, clean=1), critical_weight=5.0)

    assert result.total_burden == 5.0
    assert result.score == 0
    assert result.level == "kritisch"
