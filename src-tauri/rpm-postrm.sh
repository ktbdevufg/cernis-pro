#!/bin/sh
# Nach dem Entfernen: aufraeumen und den Benutzer ueber seine Daten aufklaeren.
#
# Beide Aufgaben gelten NUR bei der endgueltigen Entfernung, NICHT beim
# Upgrade. Beim Upgrade folgt unmittelbar die neue Fassung -- ein Hinweis
# "CERNIS PRO wurde entfernt" waere schlicht falsch, und ein Aufraeumen wuerde
# dem gerade ausgepackten Paket ins Handwerk pfuschen.
#
# UNTERSCHEIDUNG BEI rpm -- belegt an rpm-scriptlets(7) der rpm-Entwickler:
# "Scripts receive one argument ($1), which contains the number of installed
# instances of the package when the operation on the package containing the
# executing script completes." Also die Zahl der NACH der Operation
# verbleibenden Installationen: 0 heisst endgueltig entfernt, jede andere Zahl
# heisst Upgrade, Downgrade oder Parallelinstallation.
# Geprueft wird deshalb strikt auf die 0. Ein fehlendes, leeres oder nicht
# numerisches Argument gilt NICHT als endgueltige Entfernung -- im Zweifel
# schweigt und aendert dieses Skript nichts.
# (Auf der deb-Seite ist das Argument dagegen eine Zeichenkette, siehe
# deb-postrm.sh.)
#
# KEINE MEHRFACHAUSGABE AUF DIESER SEITE -- die Frage stellt sich hier gar
# nicht. Der Doppelaufruf der deb-Seite entsteht daraus, dass dpkg das Entfernen
# in zwei Schritte teilt (remove, dann purge) und postrm fuer JEDEN davon
# aufruft. rpm kennt diese Teilung nicht: es gibt kein purge und keinen
# Zustand "entfernt, aber Konfiguration noch da". Dieses Skript ist als
# postRemoveScript das %postun-Scriptlet, und rpm ruft %postun je Paket und
# Transaktion einmal auf -- mit der Zahl der danach verbleibenden
# Installationen. Ein zweiter Aufruf mit derselben 0 kommt nicht vor.
# EINSCHRAENKUNG, ehrlich benannt: auf dieser Maschine ist kein rpm
# installiert, das ist daher NICHT gemessen wie die deb-Seite, sondern aus dem
# dokumentierten Aufrufmodell abgeleitet.
#
# WARUM /bin/sh: siehe rpm-preinst.sh -- das rpm traegt zu diesen Skripten kein
# *PROG-Tag, rpm fuehrt sie mit seinem Vorgabe-Interpreter /bin/sh aus.

set -u

_cernis_verbleibend="${1-}"

# Nur eine echte, rein numerische 0 zaehlt als endgueltige Entfernung.
case "${_cernis_verbleibend}" in
    0)
        # weiter -- endgueltige Entfernung
        ;;
    *)
        exit 0
        ;;
esac

# (a) Befund 43: das zurueckgebliebene Lizenzverzeichnis.
#
# MESSUNG am gebauten Altbestand-Paket
# (target/.../bundle/rpm/CernisPro-2.1.0-1.x86_64.rpm, Kopf selbst ausgelesen):
# /usr/lib/CernisPro ist ein eigener Verzeichniseintrag (Modus 040755),
# /usr/share/licenses/cernis-pro dagegen NICHT -- dort stehen nur die beiden
# Dateien LICENSE.dependencies und LICENSES. Was rpm nicht als Verzeichnis
# kennt, raeumt rpm auch nicht ab: nach der Entfernung bleibt ein leeres
# /usr/share/licenses/cernis-pro stehen.
#
# rmdir OHNE -p und ohne -f: es entfernt ausschliesslich ein LEERES
# Verzeichnis. Liegt dort noch etwas -- ein vom Verwalter abgelegter Hinweis,
# eine Datei eines anderen Pakets --, schlaegt rmdir fehl, das Verzeichnis
# bleibt unangetastet, und wir sagen das. Genau so ist es gewollt: dieses
# Skript loescht keine fremden Inhalte.
_CERNIS_LIZENZVERZEICHNIS='/usr/share/licenses/cernis-pro'

if [ -d "${_CERNIS_LIZENZVERZEICHNIS}" ]; then
    if rmdir "${_CERNIS_LIZENZVERZEICHNIS}" 2>/dev/null; then
        :
    else
        echo "CERNIS PRO: ${_CERNIS_LIZENZVERZEICHNIS} ist nicht leer und bleibt" \
             "deshalb bestehen." >&2
    fi
fi

# (b) Hinweis auf die erhalten gebliebenen Benutzerdaten.
#
# Befund 39, Hinweisteil. Das LOESCHEN der Daten ist ausdruecklich NICHT
# Aufgabe dieses Skripts -- es kommt spaeter in die Anwendung. Ein
# Betreuerskript loescht nichts unter einem Heimatverzeichnis: es laeuft als
# Verwalter, kennt die betroffenen Benutzer nicht und koennte die Daten
# mehrerer Benutzer gleichzeitig vernichten.
echo "CERNIS PRO wurde entfernt. Ihre Daten bleiben erhalten:"
echo "~/.local/share/cernis-pro (Scans, Einstellungen) und ~/.local/share/de.cernis.pro (Oberfläche)."
echo "Diese Verzeichnisse liegen je Benutzer und werden von der Paketverwaltung bewusst nicht gelöscht."

exit 0
