#!/bin/sh
# Nach dem Entfernen: aufraeumen und den Benutzer ueber seine Daten aufklaeren.
#
# Beide Aufgaben gelten NUR bei der endgueltigen Entfernung, NICHT beim
# Upgrade. Beim Upgrade folgt unmittelbar die neue Fassung -- ein Hinweis
# "CERNIS PRO wurde entfernt" waere schlicht falsch, und ein Aufraeumen wuerde
# dem gerade ausgepackten Paket ins Handwerk pfuschen.
#
# UNTERSCHEIDUNG BEI deb -- belegt an deb-postrm(5) aus dpkg 1.22.6 auf dieser
# Maschine: das erste Argument ist eine ZEICHENKETTE, keine Zahl. Die
# Manpage nennt als Aufrufformen
#     postrm remove | purge | upgrade <ver> | failed-upgrade <alt> <neu>
#     | disappear <paket> <ver> | abort-install [...] | abort-upgrade <alt> <neu>
# Endgueltig entfernt wird bei "remove" und bei "purge". Alles andere ist
# Aktualisierung, Ruecknahme eines Fehlschlags oder Verdraengung durch ein
# anderes Paket -- dort schweigt dieses Skript.
# (Auf der rpm-Seite ist das Argument dagegen eine Zahl, siehe rpm-postrm.sh.)
#
# WARUM NUR "remove" UND NICHT AUCH "purge" MELDET -- selbst gemessen mit einem
# Wegwerfpaket gegen eine eigene dpkg-Datenbank (--admindir/--instdir im
# Sandkasten, niemals gegen das System), dpkg 1.22.6:
#     Fall 1, installiertes Paket mit purge entfernt:
#         postrm remove   <- Aufruf 1
#         postrm purge    <- Aufruf 2
#     Fall 2, bereits entferntes Paket spaeter allein nachbehandelt:
#         postrm remove   (beim seinerzeitigen Entfernen)
#         postrm purge    (beim spaeteren purge)
# dpkg(1) beschreibt genau das: "Purging of a package consists of the following
# steps: 1. Remove the package, if not already removed. See --remove for
# detailed information about how this is done. 2. Run postrm script." -- und
# --remove seinerseits endet mit "3. Run postrm script".
#
# In Fall 1 erschiene der Hinweis dadurch ZWEIMAL. Deshalb meldet allein der
# "remove"-Aufruf. Der tritt in BEIDEN Faellen genau einmal auf: in Fall 1 als
# erster der beiden Aufrufe, in Fall 2 beim urspruenglichen Entfernen. Der
# Anwender sieht den Hinweis so mindestens einmal und hoechstens einmal.
#
# WARUM NICHT STATTDESSEN IM purge-ZWEIG UNTERSCHEIDEN: die beiden Situationen
# sind aus dem Skript heraus nicht auseinanderzuhalten. Gemessen fuehrt dpkg in
# allen vier Aufrufen dieselbe Umgebung; insbesondere ist
# DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT jedes Mal 1. Es gibt kein Merkmal, an dem
# "purge unmittelbar nach eigenem remove" von "purge eines laengst entfernten
# Pakets" zu trennen waere -- eine Unterscheidung dort waere geraten.
#
# WAS DAS KOSTET, ausdruecklich benannt: wer ein Paket purged, das schon vor
# der Einfuehrung dieses postrm entfernt wurde, sieht den Hinweis nie -- damals
# lief kein postrm, das ihn haette ausgeben koennen. Dieser Fall ist einmalig
# und vergangenheitsbedingt; ihn zu bedienen hiesse, allen anderen die doppelte
# Ausgabe zuzumuten.
#
# WARUM /bin/sh: siehe deb-preinst.sh.

set -u

# Ohne Argument nichts tun. Das ist der konservative Weg: lieber einmal nicht
# melden, als bei einem Upgrade faelschlich zu melden.
_cernis_grund="${1-}"

case "${_cernis_grund}" in
    remove)
        # weiter -- endgueltige Entfernung, und der einzige Aufruf, der in
        # beiden purge-Faellen genau einmal vorkommt.
        ;;
    *)
        # Dazu gehoert ausdruecklich auch "purge": bei einem installierten
        # Paket lief der "remove"-Aufruf oben unmittelbar davor und hat den
        # Hinweis bereits ausgegeben.
        exit 0
        ;;
esac

# (a) Zurueckgebliebenes Verzeichnis.
#
# MESSUNG ZUR deb-SEITE: Befund 43 ist ein reiner rpm-Befund und tritt hier
# nicht auf. Nachgemessen am gebauten Altbestand-Paket
# (target/.../bundle/deb/CernisPro_2.1.0_amd64.deb): das deb fuehrt JEDES
# Verzeichnis als eigenen Eintrag im Datenteil -- usr/share/doc/cernis-pro,
# usr/lib/CernisPro, usr/share/icons/... Weil dpkg diese Eintraege kennt,
# raeumt es sie bei der Entfernung selbst ab, sobald sie leer sind. Es gibt
# auf der deb-Seite also KEIN Verzeichnis, das haendisch zu entfernen waere;
# ein rmdir hier waere Arbeit gegen die Paketverwaltung.
# Der rpm-Gegenpart raeumt aus genau diesem Grund /usr/share/licenses/cernis-pro
# auf: dort fehlt der Verzeichniseintrag im Paket.

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
