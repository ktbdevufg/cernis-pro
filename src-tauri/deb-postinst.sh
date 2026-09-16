#!/bin/sh
# Nach dem Auspacken: CAP_NET_RAW auf den Sniff-Helfer setzen.
#
# S5-Lehre: die Faehigkeit sitzt auf dem Sniff-Helfer cernis-sniffd, NICHT auf
# dem Backend.
#
# Befund 40: hier stand frueher
#     setcap cap_net_raw+eip /usr/bin/cernis-sniffd 2>/dev/null || true
# Das verwarf die Fehlerausgabe UND den Rueckgabewert. Schlug setcap fehl --
# fehlendes Werkzeug, Dateisystem ohne Erweiterte Attribute, read-only
# gemountetes /usr --, dann meldete die Installation Erfolg, und der Benutzer
# fand erst beim ersten Mitschnitt heraus, dass nichts geht. Genau der stille
# Fallback, den das Regelwerk verbietet.
#
# MESSUNG ZUR ABHAENGIGKEIT (entscheidet ueber den Rueckgabewert):
# setcap kommt bei Debian/Ubuntu aus libcap2-bin, bei Fedora/RHEL aus libcap,
# bei SUSE aus libcap-progs. In src-tauri/tauri.conf.json steht
#   deb  -> bundle.linux.deb.depends enthaelt woertlich "libcap2-bin"
#   rpm  -> bundle.linux.rpm.depends enthaelt woertlich "(libcap or libcap-progs)"
# Beides sind depends, also HARTE Abhaengigkeiten, keine recommends. Im
# gebauten Altbestand-Paket ist das bestaetigt: das deb fuehrt libcap2-bin in
# Depends:, das rpm fuehrt (libcap or libcap-progs) in Requires.
# FOLGE: setcap ist zugesichert. Fehlt es trotzdem oder schlaegt es fehl, ist
# das ein echter Fehler und kein hinzunehmender Umstand -- dieses Skript endet
# daher mit einem Rueckgabewert ungleich null.
#
# Befund S85-A5/2: "setcap ist installiert" und "setcap ist im Suchpfad des
# Betreuerskripts" sind zwei verschiedene Aussagen. Die Abhaengigkeit sichert
# nur die erste zu. Wie der Suchpfad wirklich aussieht, steht bei
# _cernis_finde_setcap -- dort ist die Messung festgehalten.
#
# WARUM /bin/sh UND KEIN BASH: siehe deb-preinst.sh -- das rpm traegt kein
# POSTINPROG-Tag, rpm fuehrt das Skript mit /bin/sh aus.

set -u

_CERNIS_ZIEL='/usr/bin/cernis-sniffd'
_CERNIS_FAEHIGKEIT='cap_net_raw+eip'

# Orte, an denen setcap laut den HARTEN Abhaengigkeiten dieses Pakets liegt.
# Nicht geraten, sondern am Paketinhalt belegt: "dpkg -L libcap2-bin" auf einer
# Ubuntu-Maschine liefert /usr/sbin/setcap; /sbin ist dort ein Symlink auf
# /usr/sbin (usr-merge), auf aelteren Systemen ohne usr-merge liegt es
# tatsaechlich unter /sbin. Beide Orte werden deshalb gefuehrt. Diese Liste ist
# ein NACHSCHLAG fuer den Fall, dass der Suchpfad sie nicht enthaelt -- sie
# ersetzt den Suchpfad nicht.
_CERNIS_SETCAP_ORTE='/usr/sbin/setcap /sbin/setcap'

# Findet setcap. Zuerst ueber den Suchpfad -- das ist der Normalfall und
# respektiert eine abweichende Installation des Verwalters. Erst wenn der
# Suchpfad nichts hergibt, werden die oben belegten Orte geprueft.
#
# MESSUNG DAHINTER (S85-A5/2, Wegwerfpaket gegen eine eigene dpkg-Datenbank mit
# --admindir/--instdir, dpkg 1.22.6): dpkg setzt fuer Betreuerskripte KEINEN
# eigenen Suchpfad, es reicht den PATH des Aufrufers unveraendert durch. Es
# verlangt allerdings, dass ldconfig und start-stop-daemon im PATH liegen, und
# bricht sonst vor jedem Skriptaufruf ab -- beide liegen auf Debian/Ubuntu in
# /usr/sbin, also dort, wo auch setcap liegt. In der Praxis ist /usr/sbin damit
# fast immer im Suchpfad. FAST IMMER IST ABER NICHT IMMER: gemessen wurde ein
# Lauf, in dem diese beiden Programme ueber ein anderes Verzeichnis erreichbar
# gemacht wurden -- dpkg lief an, das postinst bekam einen PATH ohne /usr/sbin,
# und "command -v setcap" fand nichts. Da dieses Skript seit Befund 40 bei
# einem Fehlschlag mit einem Wert ungleich null endet, waere das eine
# fehlgeschlagene Installation. Der Nachschlag schliesst genau diese Luecke,
# ohne den harten Rueckgabewert aufzugeben: gefunden wird ueber belegte Orte,
# nicht ueber einen geratenen Pfad, und wird nirgends etwas gefunden, bleibt es
# ein Fehler.
_cernis_finde_setcap() {
    _gefunden=$(command -v setcap 2>/dev/null) || _gefunden=''
    if [ -n "${_gefunden}" ] && [ -x "${_gefunden}" ]; then
        printf '%s\n' "${_gefunden}"
        return 0
    fi
    for _ort in ${_CERNIS_SETCAP_ORTE}; do
        if [ -x "${_ort}" ]; then
            printf '%s\n' "${_ort}"
            return 0
        fi
    done
    return 1
}

_cernis_setcap=$(_cernis_finde_setcap) || _cernis_setcap=''
if [ -z "${_cernis_setcap}" ]; then
    echo "CERNIS PRO: Die Faehigkeit ${_CERNIS_FAEHIGKEIT} konnte auf ${_CERNIS_ZIEL} nicht" \
         "gesetzt werden." >&2
    echo "CERNIS PRO: Grund: setcap wurde weder im Suchpfad (${PATH-<nicht gesetzt>}) noch" \
         "an den bekannten Orten ${_CERNIS_SETCAP_ORTE} gefunden." >&2
    echo "CERNIS PRO: Folge: Der Sniff-Helfer darf keine Pakete mitlesen. Mitschnitt und" \
         "Datenverkehrsanalyse bleiben ohne Wirkung; die uebrigen Funktionen sind nicht" \
         "betroffen." >&2
    echo "CERNIS PRO: Abhilfe: setcap ${_CERNIS_FAEHIGKEIT} ${_CERNIS_ZIEL} als Verwalter" \
         "nachholen." >&2
    exit 1
fi

# Fehlerausgabe wird MITGELESEN statt verworfen: sie nennt den Grund
# (Operation not supported, Read-only file system, ...), und der Grund ist das
# Einzige, was dem Benutzer hier weiterhilft.
# Der Status wird SOFORT gesichert. Nach einem abgeschlossenen if-Konstrukt
# waere $? dessen eigener Status (immer 0) und nicht mehr der von setcap --
# das Skript endete dann selbst im Fehlerfall mit Erfolg, also genau mit dem
# stillen Fallback, den dieser Befund abstellt.
_cernis_meldung=$("${_cernis_setcap}" "${_CERNIS_FAEHIGKEIT}" "${_CERNIS_ZIEL}" 2>&1)
_cernis_status=$?

if [ "${_cernis_status}" -eq 0 ]; then
    exit 0
fi

echo "CERNIS PRO: Die Faehigkeit ${_CERNIS_FAEHIGKEIT} konnte auf ${_CERNIS_ZIEL} nicht" \
     "gesetzt werden." >&2
if [ -n "${_cernis_meldung}" ]; then
    echo "CERNIS PRO: Grund: ${_cernis_meldung}" >&2
fi
echo "CERNIS PRO: Folge: Der Sniff-Helfer darf keine Pakete mitlesen. Mitschnitt und" \
     "Datenverkehrsanalyse bleiben ohne Wirkung; die uebrigen Funktionen sind nicht" \
     "betroffen." >&2
echo "CERNIS PRO: Abhilfe: setcap ${_CERNIS_FAEHIGKEIT} ${_CERNIS_ZIEL} als Verwalter" \
     "nachholen." >&2

exit "${_cernis_status}"
