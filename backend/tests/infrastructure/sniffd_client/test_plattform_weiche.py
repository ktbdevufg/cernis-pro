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

OHNE SYSTEMEINGRIFF: Beide Faelle werden ueber die Erkennungsstufen selbst gestellt
(``winreg.OpenKey`` / ``os.path.exists`` / ``ctypes.util.find_library``), die per
``monkeypatch`` gesetzt werden. Es wird NICHTS installiert, kein Dienst und keine
Registrierung angefasst und kein Npcap-Zustand veraendert.

STAND S65 W-d2: Die Weiche prueft FUENF Stufen statt drei. Die Erweiterung folgt einer
Messung auf einer reguleren Npcap-Installation (1.88): der Produktschluessel lag dort
nur in der 32-Bit-Sicht und der Treiber unter ``System32\\drivers``, waehrend die alten
Stufen die 64-Bit-Sicht bzw. ``System32\\Npcap`` absuchten und darum ins Leere zeigten.
Hier wird JEDE Stufe EINZELN geprueft -- nur so faellt auf, wenn eine wieder verwaist.
"""

import contextlib
import sys
from typing import Any

import pytest

from infrastructure.sniffd_client.base import (
    helper_entry_exists,
    sniffd_platform_supported,
    sniffd_unavailable_reason,
)

_NUR_WINDOWS = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows-Zweig der Weiche (nur dort erreichbar)"
)

# Die von der Weiche abgesuchten Registrierungspfade, wie die Messung sie belegt.
_DIENST_PFAD = r"SYSTEM\CurrentControlSet\Services\npcap"
_PRODUKT_PFAD = r"SOFTWARE\Npcap"


def _stufen_setzen(
    monkeypatch: pytest.MonkeyPatch,
    *,
    dienst: bool = False,
    produkt_64: bool = False,
    produkt_32: bool = False,
    treiber_drivers: bool = False,
    treiber_npcap_dir: bool = False,
    bibliothek_npcap_dir: bool = False,
    bibliothek_suche: bool = False,
) -> None:
    """Stellt JEDE Npcap-Erkennungsstufe einzeln auf Treffer/Nicht-Treffer.

    Greift genau dort an, wo die Weiche misst -- ohne echten Systemzustand zu
    veraendern. Anders als frueher wird nicht pauschal "Registrierung ja/nein"
    gesetzt, sondern nach PFAD und SICHT unterschieden; sonst liessen sich die
    Stufen 1 und 2 (und die beiden Sichten in Stufe 2) nicht auseinanderhalten:

    * Stufe 1 Dienst-/Treibereintrag  -> ``winreg.OpenKey`` auf ``_DIENST_PFAD``
    * Stufe 2 Produktschluessel       -> ``winreg.OpenKey`` auf ``_PRODUKT_PFAD``,
      je Sicht ueber ``KEY_WOW64_64KEY`` / ``KEY_WOW64_32KEY`` im ``access``-Argument
    * Stufe 3 Treiberdatei            -> ``os.path.exists`` auf ``System32\\drivers``
      bzw. ``System32\\Npcap``
    * Stufe 4 Npcap-eigene Bibliothek -> ``os.path.exists`` auf
      ``System32\\Npcap\\wpcap.dll``
    * Stufe 5 Bibliothekssuche        -> ``ctypes.util.find_library``

    Die Weiche importiert ``ctypes.util``/``winreg`` LOKAL im Windows-Zweig, darum
    werden die Modul-Attribute selbst gepatcht (nicht Namen im Weichen-Modul).
    """
    import ctypes.util
    import os
    import winreg

    def _open_key(
        key: object, sub_key: str, reserved: int = 0, access: int = 0, *args: Any
    ) -> object:
        # Ein Kontextmanager-faehiges Objekt genuegt -- die Weiche wertet nur aus,
        # ob das Oeffnen ohne OSError gelingt. Bewusst KEIN echter
        # ``winreg.OpenKey``-Aufruf: der wuerde die gepatchte Funktion erneut
        # treffen und endlos rekursieren.
        if sub_key == _DIENST_PFAD and dienst:
            return contextlib.nullcontext()
        if sub_key == _PRODUKT_PFAD:
            if access & winreg.KEY_WOW64_64KEY and produkt_64:
                return contextlib.nullcontext()
            if access & winreg.KEY_WOW64_32KEY and produkt_32:
                return contextlib.nullcontext()
        raise OSError(2, "Das System kann die angegebene Datei nicht finden")

    treffer_pfade = set()
    if treiber_drivers:
        treffer_pfade.add(("System32", "drivers", "npcap.sys"))
    if treiber_npcap_dir:
        treffer_pfade.add(("System32", "Npcap", "npcap.sys"))
    if bibliothek_npcap_dir:
        treffer_pfade.add(("System32", "Npcap", "wpcap.dll"))

    def _exists(pfad: str) -> bool:
        teile = tuple(str(pfad).replace("/", "\\").split("\\"))
        return any(teile[-len(t) :] == t for t in treffer_pfade)

    monkeypatch.setattr(winreg, "OpenKey", _open_key)
    monkeypatch.setattr(os.path, "exists", _exists)
    monkeypatch.setattr(
        ctypes.util, "find_library", lambda name: "wpcap.dll" if bibliothek_suche else None
    )


# ── Fall 1: Npcap erkannt -> nutzbar ─────────────────────────────────────────


@_NUR_WINDOWS
@pytest.mark.parametrize(
    ("stufe", "nur_diese"),
    [
        ("1 Dienst-/Treibereintrag", {"dienst": True}),
        ("2 Produktschluessel 64-Bit-Sicht", {"produkt_64": True}),
        ("2 Produktschluessel 32-Bit-Sicht", {"produkt_32": True}),
        ("3 Treiberdatei System32\\drivers", {"treiber_drivers": True}),
        ("3 Treiberdatei System32\\Npcap", {"treiber_npcap_dir": True}),
        ("4 Bibliothek System32\\Npcap", {"bibliothek_npcap_dir": True}),
        ("5 Bibliothekssuche", {"bibliothek_suche": True}),
    ],
)
def test_npcap_erkannt_macht_nutzbar(
    monkeypatch: pytest.MonkeyPatch, stufe: str, nur_diese: dict[str, bool]
) -> None:
    """JEDE Stufe ALLEIN genuegt: Npcap erkannt -> nutzbar, KEIN Marker.

    Jede Zeile setzt GENAU EINE Spur auf Treffer und laesst alle anderen leer --
    damit belegt der Fall, dass die Stufe fuer sich traegt und nicht bloss von
    einer Nachbarstufe mitgezogen wird. Die 32-Bit-Sicht in Stufe 2 hat eine
    eigene Zeile: GEMESSEN liegt der Produktschluessel dieser Npcap-Fassung
    ausschliesslich dort, waehrend die Weiche frueher nur die 64-Bit-Sicht ansah.

    Frueher lieferte der Windows-Zweig hier ``(False, "WINDOWS_IPC_UNSUPPORTED")`` --
    die Erkennung veraenderte also nur den Marker-Text, nie die Verfuegbarkeit. Genau
    das ist gefallen.
    """
    _stufen_setzen(monkeypatch, **nur_diese)
    assert sniffd_platform_supported() == (True, ""), f"Stufe {stufe} greift nicht"
    assert sniffd_unavailable_reason() == ""


# ── Fall 2: Npcap fehlt -> Npcap-Marker ──────────────────────────────────────


@_NUR_WINDOWS
def test_npcap_fehlt_liefert_npcap_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Greift KEINE EINZIGE Stufe, wird das benannt -- kein stiller Fallback.

    ``_stufen_setzen`` ohne Argumente stellt alle fuenf Stufen auf Nicht-Treffer.
    Der Marker bleibt der bestehende ``NPCAP_MISSING``; das Frontend graut die
    Funktion damit unveraendert aus und bietet die Nachinstallation an.
    """
    _stufen_setzen(monkeypatch)
    assert sniffd_platform_supported() == (False, "NPCAP_MISSING")
    assert sniffd_unavailable_reason() == "NPCAP_MISSING"


@_NUR_WINDOWS
def test_fehlendes_npcap_sperrt_den_helfer_einstieg(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ohne Npcap ist der Helfer NICHT nutzbar, auch wenn seine Datei existiert.

    ``helper_entry_exists`` fragt zuerst die Weiche -- ehrlich ``False`` statt
    faelschlich "verfuegbar".
    """
    _stufen_setzen(monkeypatch)
    assert helper_entry_exists() is False


@_NUR_WINDOWS
def test_erkanntes_npcap_gibt_den_helfer_einstieg_frei(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mit Npcap entscheidet wieder der reine Pfad-Check ueber den Helfer-Einstieg.

    Die Weiche sperrt nicht mehr vorab -- ``helper_entry_exists`` kommt bis zum
    Datei-Check durch. Npcap wird hier ueber Stufe 1 (Dienst-Eintrag) erkannt, also
    OHNE ``os.path.exists``; der anschliessende Pfad-Check auf den Helfer-Einstieg
    wird eigens auf Treffer gestellt. Die Aussage ist damit sauber "die Weiche
    laesst durch" -- getrennt von der Frage, ob die Helfer-Datei existiert.
    """
    import os

    _stufen_setzen(monkeypatch, dienst=True)
    monkeypatch.setattr(os.path, "exists", lambda pfad: True)
    assert helper_entry_exists() is True


# ── Der entfallene Marker darf nicht zurueckkehren ───────────────────────────


@_NUR_WINDOWS
@pytest.mark.parametrize(
    "lage",
    [
        {
            "dienst": True,
            "produkt_64": True,
            "produkt_32": True,
            "treiber_drivers": True,
            "treiber_npcap_dir": True,
            "bibliothek_npcap_dir": True,
            "bibliothek_suche": True,
        },
        {"produkt_32": True, "treiber_drivers": True},
        {"bibliothek_suche": True},
        {},
    ],
)
def test_kein_dritter_fall_mehr(monkeypatch: pytest.MonkeyPatch, lage: dict[str, bool]) -> None:
    """In KEINER Erkennungslage entsteht ein anderer Marker als ``NPCAP_MISSING``.

    Regressionsschutz gegen die Rueckkehr des entfallenen dritten Falls -- geprueft
    ueber alle Stufen gleichzeitig, ueber die real gemessene Lage dieser Maschine,
    ueber die schwaechste Stufe allein und ueber die leere Lage.
    """
    _stufen_setzen(monkeypatch, **lage)
    ok, marker = sniffd_platform_supported()
    assert marker in ("", "NPCAP_MISSING")
    assert ok is (marker == "")


# ── Linux/macOS bleiben unveraendert ─────────────────────────────────────────


@pytest.mark.skipif(sys.platform == "win32", reason="Nicht-Windows-Zweig der Weiche")
def test_linux_und_macos_tragen_unveraendert() -> None:
    """Ausserhalb von Windows traegt die Naht unveraendert -- ohne Npcap-Pruefung."""
    assert sniffd_platform_supported() == (True, "")
    assert sniffd_unavailable_reason() == ""
