"""Tests der Plattform-Weiche ``sniffd_platform_supported`` (Windows-Ausgrauung).

PRODUKTLINIE: Alle CERNIS-Installationen derselben Version haben denselben
Funktionsumfang. Braucht eine Funktion auf einer Plattform ein zusaetzliches Werkzeug
(hier: Npcap fuer die Rohpaket-Erfassung auf Windows), wird dieses zur Laufzeit ERKANNT
und bei Fehlen BENANNT -- die Funktion bleibt dann ehrlich ausgegraut. Fehlende
Portierungsarbeit ist kein zulaessiger Grund fuer eine fehlende Funktion.

Daraus folgen auf Windows genau ZWEI Faelle, die hier beide geprueft werden:

* Npcap erkannt -> ``(True, "")``    (Funktion verfuegbar)
* Npcap fehlt   -> ``(False, "NPCAP_MISSING")``  (ausgegraut mit Npcap-Hinweis)

Einen dritten Fall ("Npcap da, aber IPC-Naht nicht portiert") gibt es nicht mehr: die
Naht traegt auf Windows seit W2 ueber eine benannte Pipe. Der frueher dafuer gefuehrte
Marker ist ersatzlos entfallen -- kein Test darf ihn wieder einfuehren.

OHNE SYSTEMEINGRIFF: Beide Faelle werden ueber die drei Erkennungsstufen selbst
gestellt (``winreg.OpenKey`` / ``os.path.exists`` / ``ctypes.util.find_library``), die
per ``monkeypatch`` gesetzt werden. Es wird NICHTS installiert, kein Dienst und keine
Registrierung angefasst und kein Npcap-Zustand veraendert.
"""

import contextlib
import sys

import pytest

from infrastructure.sniffd_client.base import (
    helper_entry_exists,
    sniffd_platform_supported,
    sniffd_unavailable_reason,
)

_NUR_WINDOWS = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows-Zweig der Weiche (nur dort erreichbar)"
)


def _stufen_setzen(
    monkeypatch: pytest.MonkeyPatch,
    *,
    registry: bool,
    treiber: bool,
    bibliothek: bool,
) -> None:
    """Stellt die drei Npcap-Erkennungsstufen einzeln auf Treffer/Nicht-Treffer.

    Greift genau dort an, wo die Weiche misst -- ohne echten Systemzustand zu
    veraendern:

    * Stufe 1 Registrierungsschluessel -> ``winreg.OpenKey``
    * Stufe 2 Treiberdatei             -> ``os.path.exists``
    * Stufe 3 Bibliothekssuche         -> ``ctypes.util.find_library``

    Die Weiche importiert ``ctypes.util``/``winreg`` LOKAL im Windows-Zweig, darum
    werden die Modul-Attribute selbst gepatcht (nicht Namen im Weichen-Modul).
    """
    import ctypes.util
    import os
    import winreg

    def _open_key(*args: object, **kwargs: object) -> object:
        if registry:
            # Ein Kontextmanager-faehiges Objekt genuegt -- die Weiche wertet nur
            # aus, ob das Oeffnen ohne OSError gelingt. Bewusst KEIN echter
            # ``winreg.OpenKey``-Aufruf: der wuerde die gepatchte Funktion erneut
            # treffen und endlos rekursieren.
            return contextlib.nullcontext()
        raise OSError(2, "Das System kann die angegebene Datei nicht finden")

    monkeypatch.setattr(winreg, "OpenKey", _open_key)
    monkeypatch.setattr(os.path, "exists", lambda pfad: treiber)
    monkeypatch.setattr(
        ctypes.util, "find_library", lambda name: "wpcap.dll" if bibliothek else None
    )


# ── Fall 1: Npcap erkannt -> nutzbar ─────────────────────────────────────────


@_NUR_WINDOWS
@pytest.mark.parametrize(
    ("registry", "treiber", "bibliothek", "stufe"),
    [
        (True, False, False, "Registrierungsschluessel"),
        (False, True, False, "Treiberdatei"),
        (False, False, True, "Bibliothekssuche"),
    ],
)
def test_npcap_erkannt_macht_nutzbar(
    monkeypatch: pytest.MonkeyPatch,
    registry: bool,
    treiber: bool,
    bibliothek: bool,
    stufe: str,
) -> None:
    """JEDE der drei Stufen allein genuegt: Npcap erkannt -> nutzbar, KEIN Marker.

    Frueher lieferte der Windows-Zweig hier ``(False, "WINDOWS_IPC_UNSUPPORTED")`` --
    die Erkennung veraenderte also nur den Marker-Text, nie die Verfuegbarkeit. Genau
    das ist gefallen.
    """
    _stufen_setzen(monkeypatch, registry=registry, treiber=treiber, bibliothek=bibliothek)
    assert sniffd_platform_supported() == (True, ""), f"Stufe {stufe} greift nicht"
    assert sniffd_unavailable_reason() == ""


# ── Fall 2: Npcap fehlt -> Npcap-Marker ──────────────────────────────────────


@_NUR_WINDOWS
def test_npcap_fehlt_liefert_npcap_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Schlagen ALLE drei Stufen fehl, wird das benannt -- kein stiller Fallback.

    Der Marker bleibt der bestehende ``NPCAP_MISSING``; das Frontend graut die
    Funktion damit unveraendert aus und bietet die Nachinstallation an.
    """
    _stufen_setzen(monkeypatch, registry=False, treiber=False, bibliothek=False)
    assert sniffd_platform_supported() == (False, "NPCAP_MISSING")
    assert sniffd_unavailable_reason() == "NPCAP_MISSING"


@_NUR_WINDOWS
def test_fehlendes_npcap_sperrt_den_helfer_einstieg(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ohne Npcap ist der Helfer NICHT nutzbar, auch wenn seine Datei existiert.

    ``helper_entry_exists`` fragt zuerst die Weiche -- ehrlich ``False`` statt
    faelschlich "verfuegbar".
    """
    _stufen_setzen(monkeypatch, registry=False, treiber=False, bibliothek=False)
    assert helper_entry_exists() is False


@_NUR_WINDOWS
def test_erkanntes_npcap_gibt_den_helfer_einstieg_frei(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mit Npcap entscheidet wieder der reine Pfad-Check ueber den Helfer-Einstieg.

    Die Weiche sperrt nicht mehr vorab -- ``helper_entry_exists`` kommt bis zum
    Datei-Check durch. ``os.path.exists`` steht durch ``treiber=True`` auf True,
    damit sowohl Stufe 2 als auch der anschliessende Pfad-Check positiv sind; die
    Aussage ist also "die Weiche laesst durch", nicht "die Datei existiert".
    """
    _stufen_setzen(monkeypatch, registry=False, treiber=True, bibliothek=False)
    assert helper_entry_exists() is True


# ── Der entfallene Marker darf nicht zurueckkehren ───────────────────────────


@_NUR_WINDOWS
@pytest.mark.parametrize(
    ("registry", "treiber", "bibliothek"),
    [(True, True, True), (False, False, True), (False, False, False)],
)
def test_kein_dritter_fall_mehr(
    monkeypatch: pytest.MonkeyPatch, registry: bool, treiber: bool, bibliothek: bool
) -> None:
    """In KEINER Erkennungslage entsteht ein anderer Marker als ``NPCAP_MISSING``.

    Regressionsschutz gegen die Rueckkehr des entfallenen dritten Falls.
    """
    _stufen_setzen(monkeypatch, registry=registry, treiber=treiber, bibliothek=bibliothek)
    ok, marker = sniffd_platform_supported()
    assert marker in ("", "NPCAP_MISSING")
    assert ok is (marker == "")


# ── Linux/macOS bleiben unveraendert ─────────────────────────────────────────


@pytest.mark.skipif(sys.platform == "win32", reason="Nicht-Windows-Zweig der Weiche")
def test_linux_und_macos_tragen_unveraendert() -> None:
    """Ausserhalb von Windows traegt die Naht unveraendert -- ohne Npcap-Pruefung."""
    assert sniffd_platform_supported() == (True, "")
    assert sniffd_unavailable_reason() == ""
