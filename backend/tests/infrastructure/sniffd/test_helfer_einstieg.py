"""Tests fuer den Helfer-Einstieg ``backend/sniffd.py`` (Startbefehl-Seite).

Der Einstieg hatte als Vorgabewert einen fest verdrahteten Linux-Pfad
(``/tmp/cernis-sniffd.sock``). Auf Windows ist das kein gueltiger Pipe-Name --
ein Start ohne Argument waere dort in einen unverstaendlichen Fehler tief in der
Transportnaht gelaufen, statt den Aufrufsfehler zu benennen.

Geprueft wird darum: ohne Adresse endet der Einstieg mit einem klaren Hinweis
und einem von 0 verschiedenen Rueckgabewert -- auf JEDER Plattform gleich, ohne
Annahme ueber Pfadtrenner oder Pipe-Namen.
"""

import subprocess
import sys
from pathlib import Path

_SNIFFD = Path(__file__).resolve().parents[3] / "sniffd.py"
_BACKEND = Path(__file__).resolve().parents[3]


def _starte_einstieg(*argumente: str) -> "subprocess.CompletedProcess[str]":
    """Ruft ``sniffd.py`` als echten Prozess auf (Import-Wurzel ist ``backend/``)."""
    return subprocess.run(
        [sys.executable, str(_SNIFFD), *argumente],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(_BACKEND),
    )


def test_einstieg_ohne_adresse_benennt_den_aufrufsfehler() -> None:
    """Kein Argument -> klarer Hinweis auf stderr, Rueckgabewert != 0 (kein stiller Rateweg)."""
    ergebnis = _starte_einstieg()

    assert ergebnis.returncode != 0, "Einstieg ohne Adresse endete als Erfolg"
    assert "Aufruf" in ergebnis.stderr
    # Der frueher geratene Linux-Vorgabewert taucht nirgends mehr auf.
    assert "/tmp/cernis-sniffd.sock" not in ergebnis.stderr
    assert "/tmp/cernis-sniffd.sock" not in ergebnis.stdout


def test_einstieg_mit_leerer_adresse_benennt_den_aufrufsfehler() -> None:
    """Eine leere Adresse ist ebenso ein Aufrufsfehler und wird nicht stillschweigend ersetzt."""
    ergebnis = _starte_einstieg("")

    assert ergebnis.returncode != 0
    assert "Aufruf" in ergebnis.stderr


def test_einstieg_datei_existiert_und_ist_der_dev_startpunkt() -> None:
    """Der Einstieg, auf den das dev-Spawn-Kommando zeigt, existiert wirklich."""
    from infrastructure.sniffd_client import base

    if base._is_frozen():  # pragma: no cover -- im Testlauf nie frozen
        return
    cmd = base._spawn_command("adresse")
    assert Path(cmd[1]) == _SNIFFD
    assert _SNIFFD.exists()
