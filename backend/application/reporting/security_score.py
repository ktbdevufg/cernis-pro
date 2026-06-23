"""Netz-Gesundheit-Score fuer den Sicherheitsbericht als reine, zeitfreie Rechnung (Etappe 1).

Diese Datei verdichtet je Geraet die schwerste offene Auffaelligkeit (worst_severity)
zu einem aggregierten Netz-Gesundheit-Score 0..100 mit Einstufung (gut/maessig/kritisch)
und den begleitenden Zaehlern. Sie ist REINE RECHNUNG analog behavior_profile.py:
KEINE Uhr, KEINE I/O, KEINE Persistenz, KEINE Anbindung an CVE/analysis/security/
dns_watch -- das Maximum ueber alle Quellen je Geraet bestimmt der Aufrufer (Etappe 2)
am Composition Root und reicht es bereits verdichtet als DeviceBurden herein.

KEINE Domaenen-Importe (CLAUDE.md, Importregel application -> domain/ports): diese
Schicht rechnet ausschliesslich mit den hier definierten frozen-Datentraegern. Die
Gewichte und Schwellen kommen als Parameter mit Defaults herein (spaeter aus
analysis-Settings), nicht hartkodiert -- dieselbe Naht wie die slot_minutes/
deviation_factor-Parameter bei behavior_profile.

Muster aus der Nachbarschaft uebernommen: frozen dataclasses als Ein-/Ausgabe-
Datentraeger, reine Funktionen mit ausfuehrlichen Docstrings, alle Kontextwerte
via Parameter, deterministisch ohne Wanduhr.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Eingabe-Datentraeger (frozen) ───────────────────────────────────────────


@dataclass(frozen=True)
class DeviceBurden:
    """Die Last EINES Geraets fuer den Netz-Gesundheit-Score.

    ``device_label`` ist der Anzeigename oder ip||mac, vom Aufrufer gesetzt.
    ``worst_severity`` ist genau einer von "critical" / "notable" / "none" und
    benennt das SCHWERSTE offene (nicht quittierte) Vergehen dieses Geraets ueber
    ALLE Quellen hinweg (Ports/CVE/Netz). Das Maximum bestimmt der Aufrufer
    (Etappe 2); diese Datei rechnet nur damit.

    "none" = keine offene Auffaelligkeit (sauberes Geraet). Quittierte Befunde
    liefert der Aufrufer gar nicht erst als Vergehen ein -- sie tauchen also als
    "none" auf bzw. senken die worst_severity entsprechend.
    """

    device_label: str
    worst_severity: str


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class SecurityScore:
    """Das Gesamtergebnis der Score-Rechnung (alles, was der Bericht herausreicht).

    ``score`` ist der Netz-Gesundheit-Wert 0..100 (geclamped), ``level`` die
    Einstufung "gut" / "maessig" / "kritisch", ``device_count`` die Basis N
    (Anzahl beruecksichtigter Geraete), ``total_burden`` die aufsummierte Last,
    ``critical_devices`` / ``notable_devices`` / ``clean_devices`` die Zaehler je
    worst_severity-Stufe (critical / notable / none).
    """

    score: int
    level: str
    device_count: int
    total_burden: float
    critical_devices: int
    notable_devices: int
    clean_devices: int


# ── Reine Funktion (keine I/O, keine Uhr) ───────────────────────────────────


def compute_security_score(
    burdens: list[DeviceBurden],
    critical_weight: float = 1.0,
    # notable_weight Default 0.3334 entspricht rund einem Drittel der Last eines
    # kritischen Befunds -- drei offene "notable" wiegen etwa ein "critical" auf.
    notable_weight: float = 0.3334,
    level_good_min: int = 80,
    level_mid_min: int = 50,
) -> SecurityScore:
    """Berechnet den Netz-Gesundheit-Score aus den Geraete-Lasten.

    Lastwert je Geraet: "critical" -> ``critical_weight``, "notable" ->
    ``notable_weight``, "none" -> 0.0. ``device_count`` N ist die Zahl der
    Geraete, ``total_burden`` die Summe der Lastwerte.

    ``score = round(100 * (1 - total_burden / N))``, geclamped auf [0, 100].
    Bei N == 0 -> score 100 und level "gut": ein leeres/sauberes Netz hat kein
    beruecksichtigtes Geraet und damit keine Last -- ehrlicher Default statt
    Division durch Null (kein Geraet = keine Last = bestmoeglicher Wert).

    ``level``: score >= ``level_good_min`` -> "gut"; sonst score >=
    ``level_mid_min`` -> "maessig"; sonst "kritisch".

    Die Gewichte und Schwellen kommen als Parameter mit Defaults herein (spaeter
    aus analysis-Settings), nicht hartkodiert. Deterministisch, keine Uhr, keine I/O.
    """
    critical_devices = sum(1 for burden in burdens if burden.worst_severity == "critical")
    notable_devices = sum(1 for burden in burdens if burden.worst_severity == "notable")
    clean_devices = sum(1 for burden in burdens if burden.worst_severity == "none")

    total_burden = critical_devices * critical_weight + notable_devices * notable_weight
    device_count = len(burdens)

    if device_count == 0:
        # Kein beruecksichtigtes Geraet = keine Last: bestmoeglicher, ehrlicher
        # Default statt Division durch Null.
        score = 100
    else:
        raw_score = round(100 * (1 - total_burden / device_count))
        score = max(0, min(100, raw_score))

    if score >= level_good_min:
        level = "gut"
    elif score >= level_mid_min:
        level = "maessig"
    else:
        level = "kritisch"

    return SecurityScore(
        score=score,
        level=level,
        device_count=device_count,
        total_burden=total_burden,
        critical_devices=critical_devices,
        notable_devices=notable_devices,
        clean_devices=clean_devices,
    )
