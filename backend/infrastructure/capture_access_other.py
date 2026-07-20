"""Nicht-macOS-Adapter fuer ``CaptureAccessPort``: ehrliches "trifft hier nicht zu".

Erfuellt den ``CaptureAccessPort`` strukturell, ohne etwas einzurichten. Die
BPF-Geraeteknoten ``/dev/bpf*`` und der LaunchDaemon-Mechanismus sind macOS-Konzepte;
auf Linux wird der rohe Mitschnitt ueber ``CAP_NET_RAW`` auf ``cernis-sniffd`` geregelt
(gesetzt im Paket-Postinstall, im Dev ueber ``scripts/dev-setcap-sniffd.sh``).

Bewusst KEIN Fehler und KEIN vorgetaeuschter Erfolg (S3): alle drei Operationen
(Status, Einrichtung, Widerruf) melden den eigenen Zustand ``NOT_APPLICABLE`` mit
klarer Begruendung. Der api-Rand kann das
ehrlich weiterreichen, statt der Oberflaeche eine Einrichtung anzubieten, die es hier
nicht gibt.

Muster der Plattform-Weiche wie ``interfaces_linux``/``interfaces_macos`` bzw.
``traffic_linux``/``traffic_macos``: gleicher Klassenname in beiden Zweigen, die
Auswahl trifft der Composition Root (``app.py``).
"""

from domain.capture_access import (
    CaptureAccessOutcome,
    CaptureAccessResult,
    CaptureAccessRevokeOutcome,
    CaptureAccessRevokeResult,
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
        """Immer ``NOT_APPLICABLE`` mit Begruendung -- hier gibt es diese Einrichtung nicht.

        ``members`` bleibt leer (Default): eine Capture-Gruppe existiert auf dieser
        Plattform nicht, es gibt also niemanden zu nennen. Kein erfundener Inhalt.
        """
        return CaptureAccessStatus(
            state=CaptureAccessState.NOT_APPLICABLE, detail=_NOT_APPLICABLE_DETAIL
        )

    def grant(self) -> CaptureAccessResult:
        """Immer ``NOT_APPLICABLE`` -- es wird nichts eingerichtet und nichts vorgetaeuscht."""
        return CaptureAccessResult(
            outcome=CaptureAccessOutcome.NOT_APPLICABLE, reason=_NOT_APPLICABLE_DETAIL
        )

    def revoke(self, nur_mitgliedschaft: bool) -> CaptureAccessRevokeResult:
        """Immer ``NOT_APPLICABLE`` -- was hier nie eingerichtet wurde, ist nicht widerrufbar.

        ``nur_mitgliedschaft`` wird bewusst ignoriert: es gibt weder eine Gruppe noch
        einen Systemdienst, den ein Modus unterscheiden koennte. Der Parameter bleibt
        Teil der Signatur, weil der Port ihn vorschreibt.
        """
        return CaptureAccessRevokeResult(
            outcome=CaptureAccessRevokeOutcome.NOT_APPLICABLE, reason=_NOT_APPLICABLE_DETAIL
        )
