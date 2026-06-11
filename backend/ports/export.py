"""Ports der export-Domaene (Block 1): der Vertrag fuer das PDF-Rendern.

EIN Vertrag, getrennt nach Belang (CSV/JSON brauchen KEINEN Port -- sie sind reine
``domain.export``-Funktionen ohne I/O; nur das PDF-Rendern ist Infrastruktur):

* ``ReportRenderer`` -- die PDF-RENDER-Senke. ``render_pdf`` nimmt das reine
  ``PdfReportModel`` (Kopf-Felder + Tabellen-Zeilen, von ``domain.build_pdf_model`` gebaut)
  und liefert die fertigen PDF-Bytes. SYNCHRON: reportlab ist CPU-/Render-Arbeit, kein
  Netz-I/O -- ehrlich kein ``async`` (anders als die diagnostics-Daten-Ports, die System-
  Tooling/Netz kapseln). Faellt im Use-Case async-Kontext an, kapselt das der Use-Case/
  Adapter; das Rendern selbst bleibt sync.

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/scanning/
diagnostics). Die Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung im
Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

``ports/`` kennt NUR ``domain/export``-Typen + stdlib/typing. KEIN ``infrastructure/``-
Import -- import-linter-Contract "ports kennen hoechstens domain". Import von ``domain`` ist
erlaubt (nur die Gegenrichtung ist verboten).
"""

from typing import Protocol

from domain.export import PdfReportModel


class ReportRenderer(Protocol):
    """Render-Senke der export-Domaene: ein ``PdfReportModel`` zu PDF-Bytes."""

    def render_pdf(self, model: PdfReportModel) -> bytes:
        """Rendert das reine ``PdfReportModel`` zu fertigen PDF-Bytes.

        Nimmt die reine Struktur (Kopf-Felder + Tabellen-Zeilen, von
        ``domain.build_pdf_model`` gebaut) und liefert ein valides PDF als ``bytes``. KEINE
        Domaenen-Logik im Adapter -- nur das Rendern der vorgegebenen Struktur (Spalten/
        Zeilen/Kopf liegen bereits fest). SYNCHRON: reportlab ist CPU-/Render-Arbeit ohne
        Netz-I/O, daher ehrlich kein ``async`` (der Use-Case/Adapter kapselt, falls noetig).
        """
        ...
