"""Nicht-macOS-Adapter fuer ``CaptureAccessPort``: ehrliches "trifft hier nicht zu".

Erfuellt den ``CaptureAccessPort`` strukturell, ohne etwas einzurichten. Die
BPF-Geraeteknoten ``/dev/bpf*`` und der LaunchDaemon-Mechanismus sind macOS-Konzepte;
auf Linux wird der rohe Mitschnitt ueber ``CAP_NET_RAW`` auf ``cernis-sniffd`` geregelt
(gesetzt im Paket-Postinstall, im Dev ueber ``scripts/dev-setcap-sniffd.sh``).

Bewusst KEIN Fehler und KEIN vorgetaeuschter Erfolg (S3): beide Operationen melden den
eigenen Zustand ``NOT_APPLICABLE`` mit klarer Begruendung. Der api-Rand kann das
ehrlich weiterreichen, statt der Oberflaeche eine Einrichtung anzubieten, die es hier
nicht gibt.

Muster der Plattform-Weiche wie ``interfaces_linux``/``interfaces_macos`` bzw.
``traffic_linux``/``traffic_macos``: gleicher Klassenname in beiden Zweigen, die
Auswahl trifft der Composition Root (``app.py``).
"""

from domain.capture_access import (
    CaptureAccessOutcome,
    CaptureAccessResult,
    CaptureAccessState,
    CaptureAccessStatus,
)

# Begruendung fuer beide Operationen -- benennt zugleich den Weg, der auf dieser
# Plattform tatsaechlich gilt (handlungsorientiert statt nur "nicht verfuegbar").
_NOT_APPLICABLE_DETAIL = (
    "Diese Einrichtung gilt nur fuer macOS. Auf anderen Plattformen wird der "
    "Zugriff anders geregelt (Linux: CAP_NET_RAW ueber das Paket-Postinstall)."
)


class CaptureAccessAdapter:
    """Erfuellt ``CaptureAccessPort`` ausserhalb von macOS (immer ``NOT_APPLICABLE``)."""

    def status(self) -> CaptureAccessStatus:
        """Immer ``NOT_APPLICABLE`` mit Begruendung -- hier gibt es diese Einrichtung nicht."""
        return CaptureAccessStatus(
            state=CaptureAccessState.NOT_APPLICABLE, detail=_NOT_APPLICABLE_DETAIL
        )

    def grant(self) -> CaptureAccessResult:
        """Immer ``NOT_APPLICABLE`` -- es wird nichts eingerichtet und nichts vorgetaeuscht."""
        return CaptureAccessResult(
            outcome=CaptureAccessOutcome.NOT_APPLICABLE, reason=_NOT_APPLICABLE_DETAIL
        )
