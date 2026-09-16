"""Robuste Aufloesung gebundelter Datenpfade -- frozen (PyInstaller) vs. Entwicklung.

Kleiner, reiner Infrastruktur-Helfer (nur stdlib). Im PyInstaller-Bundle liegen die per Spec
mitgegebenen Datenfiles unter ``sys._MEIPASS`` (dem entpackten Temp-Root); im Entwicklungs-Baum
existiert dieses Attribut nicht und die Dateien liegen an ihrem Repo-Pfad. ``resolve_bundle_path``
kapselt genau diese Fallunterscheidung an EINER Stelle, damit sowohl ``export_pdf.py`` (Logo) als
auch der ``app.py``-Runner (help_content.json) denselben, robusten Weg nutzen.

Import-linter-konform: liegt in ``infrastructure/`` und importiert nur stdlib -- ``export_pdf.py``
(selbst ``infrastructure/``) und ``app.py`` (Composition Root, darf ``infrastructure`` verdrahten)
duerfen ihn beide nutzen, ohne eine Ring-Kante zu verletzen.
"""

import os
import sys


def is_frozen() -> bool:
    """``True`` im PyInstaller-Bundle (Muster ``serve.py``/``sniffd_client``)."""
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def resolve_bundle_path(*, frozen_relative: str, dev_absolute: str) -> str:
    """Loest einen gebundelten Datenpfad robust auf: frozen relativ zu ``_MEIPASS``, sonst dev.

    Im Frozen-Build (``is_frozen()`` UND ``sys._MEIPASS`` gesetzt) wird ``frozen_relative``
    relativ zum entpackten Bundle-Root (``sys._MEIPASS``) aufgeloest -- dort landen die per Spec
    mitgegebenen Datenfiles. Sonst (Entwicklung, oder Frozen ohne ``_MEIPASS``) gilt der bereits
    normalisierte ``dev_absolute``-Pfad unveraendert. Rueckgabe ist ein normalisierter Pfad; ob
    die Datei tatsaechlich existiert, entscheidet der Aufrufer (ehrlicher Leerfall bleibt moeglich).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if is_frozen() and meipass:
        return os.path.normpath(os.path.join(meipass, frozen_relative))
    return dev_absolute
