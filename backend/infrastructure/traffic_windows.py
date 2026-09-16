"""Windows-Adapter fuer ``TrafficPermissionPort`` -- der bewusste Verzicht, benannt.

Erfuellt den BESTEHENDEN ``TrafficPermissionPort`` strukturell (schnelle, synchrone,
lokale Auskunft ohne Netz-/Loop-I/O), genau wie ``traffic_permission`` (Linux) und
``traffic_macos``. Der Port bleibt unveraendert; hier kommt nur eine dritte Antwort
darauf hinzu.

MESSBEFUND (S67, Finding 12): Windows liefert Byte-Mengen je Programm sehr wohl --
ueber die Ereignisablaufverfolgung (ETW), je Ereignis mit den Feldern PID und size;
zwoelf Prozesse wurden so aufgeloest, und der Dateiverkehr floss nicht in die
Netzzaehlung. Die Messung ist also technisch moeglich. Der Zugang verlangt aber
DAUERHAFT erhoehte Rechte: vier Wege wurden gemessen und scheiterten allesamt --
unprivilegiert anlegen, eine laufende Sitzung mitlesen, die Gruppe
"Leistungsprotokollbenutzer", und das Richtlinien-Privileg
``SeSystemProfilePrivilege`` auch bei Selbst-Aktivierung durch den Prozess.

DIE ENTSCHEIDUNG (Karl, S67): die Funktion wird auf Windows bewusst NICHT gebaut.
Der Preis waere der erste dauerhaft privilegierte Prozess im Produkt. Das ist eine
Produktentscheidung, kein technisches Scheitern -- und dieser Adapter sagt genau
das, statt ein Unvermoegen vorzutaeuschen.

WARUM ``NOT_APPLICABLE`` UND NICHT ``NEEDS_PRIVILEGES``: der Unterschied zwischen
den beiden Zustaenden ist BEHEBBAR gegen NICHT BEHEBBAR (Begruendung an
``TrafficPermissionState``). Fuer die Oberflaeche ist der Verzicht so wenig behebbar
wie eine Plattformgrenze: es gibt nichts einzurichten, nichts nachzuinstallieren und
nichts zu raten. ``NEEDS_PRIVILEGES`` wuerde einen Weg versprechen, den CERNIS nicht
anbietet -- und die Oberflaeche wuerde folgerichtig einen Hinweis stehen lassen, der
zu einer Handlung auffordert, die es nicht gibt. Die URSACHE
``PRIVILEGE_DECLINED`` haelt den Unterschied zur echten Plattformgrenze (macOS)
trotzdem maschinell auswertbar fest, statt ihn im Freitext zu verstecken.

WAS AUF WINDOWS FUNKTIONIERT: Stufe 1 vollstaendig und rechtefrei -- welches Programm
mit welcher Gegenstelle spricht, Verbindungszahl, Ziel und Port. Darum meldet
``is_available`` ``True``: der Feature-Bereich ist nutzbar, nur die Durchsatz-Zeile
bleibt leer. Ein ``False`` wuerde den ganzen Bereich sperren und damit eine
funktionierende Sicht verschenken.

Der Adapter verschafft sich NIE Rechte, fordert keine an und nennt auch keinen Weg
zu welchen -- weder im Text noch als Schaltflaeche (Karls Entscheidung S57/S67).

Vorbild fuer Aufbau und Ton: ``traffic_macos.TrafficPermissionAdapter`` (derselbe
Zustand, dieselbe Dreiteilung der Antworten). Vorbild fuer einen Windows-Adapter
hinter einem bestehenden Port: ``traceroute_windows.WindowsTraceroutePermission``.
"""

from domain.traffic import (
    TrafficPermissionCause,
    TrafficPermissionResult,
    TrafficPermissionState,
)

# Begruendung des Verzichts. Benennt WAS fehlt, WARUM es fehlt und WAS trotzdem
# funktioniert -- und enthaelt bewusst KEINE Handlungsaufforderung: kein Befehl,
# kein Rechte-Rat, kein Versprechen fuer spaeter. Die Oberflaeche zeigt ihren
# eigenen, uebersetzten Text; dieser Grund ist die technische Begruendung fuer
# Protokoll und API-Aufrufer (Muster ``traffic_macos._NOT_APPLICABLE_REASON``).
_PRIVILEGE_DECLINED_REASON = (
    "Wie viele Daten ein einzelnes Programm uebertraegt, zeigt CERNIS unter Windows "
    "nicht: das Betriebssystem gibt diese Zahlen nur an Programme heraus, die "
    "dauerhaft mit erhoehten Rechten laufen. CERNIS verzichtet bewusst darauf. "
    "Welches Programm mit welcher Gegenstelle spricht, wird vollstaendig angezeigt."
)


class TrafficPermissionAdapter:
    """Erfuellt das ``TrafficPermissionPort``-Protocol (Windows: bewusster Verzicht)."""

    def is_available(self) -> bool:
        """Immer ``True`` -- Stufe 1 laeuft auf Windows vollstaendig und rechtefrei.

        Die Verbindungssicht (welches Programm, welche Gegenstelle, welcher Port)
        steht ohne jede Rechteerhoehung. Nur die Durchsatz-Zeile bleibt leer, und das
        sagt ``permission_state`` mit Grund. Ein ``False`` wuerde den ganzen
        Feature-Bereich sperren, obwohl der groessere Teil davon arbeitet.
        """
        return True

    def check_permission(self) -> str | None:
        """Der Verzichts-Grund als schmale Text-Naht (bestehende Wire-Form ``error``).

        Dass es sich um einen bewussten Verzicht und nicht um ein behebbares
        Rechteproblem handelt, sagen ``state`` und ``cause`` aus ``permission_state``
        -- nicht dieser Text (Muster ``traffic_macos``).
        """
        return _PRIVILEGE_DECLINED_REASON

    def permission_state(self) -> TrafficPermissionResult:
        """Immer ``NOT_APPLICABLE`` mit der Ursache ``PRIVILEGE_DECLINED`` und Grund.

        Bewusst NICHT ``NEEDS_PRIVILEGES``: dieser Zustand bedeutet "behebbar, hier ist
        der Weg" -- und einen Weg gibt es nicht, weil CERNIS ihn nicht anbietet. Die
        Ursache haelt den Unterschied zur echten Plattformgrenze (macOS, ``cause``
        ``None``) trotzdem fest, damit die Oberflaeche den richtigen Text waehlen kann,
        ohne ihn aus dem Freitext zu erraten.
        """
        return TrafficPermissionResult(
            state=TrafficPermissionState.NOT_APPLICABLE,
            reason=_PRIVILEGE_DECLINED_REASON,
            cause=TrafficPermissionCause.PRIVILEGE_DECLINED,
        )
