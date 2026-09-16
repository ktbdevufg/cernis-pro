#!/bin/sh
# Vor dem Auspacken: die drei ausgelieferten Programme geordnet beenden.
#
# Befund 41: hier stand frueher "killall -9 cernis-backend" gefolgt von einem
# pauschalen "sleep 1". Das war in drei Punkten falsch:
#   1. killall trifft ueber den NAMEN. Ein fremder Prozess, der zufaellig
#      "cernis-backend" heisst, wurde miterschlagen.
#   2. SIGKILL sofort -- kein geordnetes Beenden, offene Dateien und die
#      Datenbank blieben in unklarem Zustand.
#   3. "sleep 1" ist geraten. Ist der Prozess schneller weg, wird gewartet;
#      braucht er laenger, wird trotzdem weitergemacht.
# Ersetzt durch _cernis_beende_programme(): Auswahl ueber den exe-Symlink,
# erst SIGTERM, dann gepolltes Warten auf das ECHTE Ende, SIGKILL nur als
# letztes Mittel.
#
# WARUM /bin/sh UND KEIN BASH: das rpm traegt zu diesem Skript kein
# PREINPROG-Tag (nachgemessen am gebauten Paket), also fuehrt rpm es mit
# seinem Vorgabe-Interpreter /bin/sh aus. Die Zeile "#!/bin/bash" war dort
# wirkungslos -- reiner Kommentar. Dieses Skript ist daher streng POSIX.

set -u

# Die drei Programme, die das Paket nach /usr/bin liefert.
# Reihenfolge ist Absicht, siehe _cernis_beende_programme().
_CERNIS_PROGRAMME='cernis-pro cernis-backend cernis-sniffd'

# Verzeichnis, in dem eine Programmdatei liegen MUSS, damit wir sie anfassen.
_CERNIS_BINDIR='/usr/bin'

# Obergrenze fuer das Warten auf ein geordnetes Ende, in Zehntelsekunden.
# 100 = 10 Sekunden. Begruendung: das Backend schliesst beim SIGTERM die
# SQLite-Datenbank und laufende Scans ab; 10 s decken das mit Reserve, ohne
# eine Paketinstallation spuerbar aufzuhalten.
_CERNIS_FRIST_ZEHNTEL=100

# Wahr, wenn die Kennung $1 GERADE JETZT zu ${_CERNIS_BINDIR}/$2 gehoert.
#
# ZWINGEND ueber den exe-Symlink, nicht ueber den Namen: nur so bleibt ein
# gleichnamiger Prozess aus einem Entwicklungsbaum oder aus /opt unangetastet.
# Ist der Symlink nicht lesbar (fremder Benutzer, Prozess bereits beendet),
# gilt das als "nicht unseres" -- Unklarheit ist kein Trefferkriterium.
#
# Der Kernel haengt " (deleted)" an, sobald die Programmdatei ersetzt wurde.
# Genau das ist beim Upgrade der Normalfall: die alte Datei ist schon weg,
# der Prozess laeuft aber weiter aus dem Installationsverzeichnis. Diese eine
# Form wird deshalb ebenfalls als Treffer gewertet, sonst griffe die Auswahl
# beim Upgrade nie. Jede andere Abweichung ist kein Treffer.
#
# WARUM NICHT pgrep: pgrep kommt aus procps, und procps steht weder in den
# deb- noch in den rpm-Abhaengigkeiten. Ein Skript, das sich auf ein nicht
# zugesichertes Paket stuetzt, ist genau der stille Fallback, den wir hier
# gerade abstellen. /proc ist Kernel-Schnittstelle und immer da.
#
# Befund S85-A5/1: diese Pruefung ist die EINZIGE Stelle, an der ueber die
# Zugehoerigkeit einer Kennung entschieden wird. Sowohl die Auswahl als auch
# das Warten als auch jedes Signal fragen hier -- damit gilt fuer alle drei
# derselbe Massstab, und es gibt keine zweite Bauart daneben.
_cernis_ist_unseres() {
    _kandidat="$1"
    _erwartet="${_CERNIS_BINDIR}/$2"
    _gefunden=$(readlink "/proc/${_kandidat}/exe" 2>/dev/null) || return 1
    [ -n "${_gefunden}" ] || return 1
    [ "${_gefunden}" = "${_erwartet}" ] || [ "${_gefunden}" = "${_erwartet} (deleted)" ]
}

# Gibt die Kennungen aus, deren Programmdatei genau ${_CERNIS_BINDIR}/$1 ist.
_cernis_pids_von() {
    _name="$1"
    for _eintrag in /proc/[0-9]*; do
        [ -d "${_eintrag}" ] || continue
        _kennung="${_eintrag#/proc/}"
        if _cernis_ist_unseres "${_kennung}" "${_name}"; then
            printf '%s\n' "${_kennung}"
        fi
    done
}

# Beendet alle drei Programme geordnet.
#
# REIHENFOLGE cernis-pro -> cernis-backend -> cernis-sniffd, und zwar entlang
# der Abhaengigkeitskette von aussen nach innen:
#   * cernis-pro ist die Oberflaeche und der einzige Auftraggeber des Backends.
#     Sie zuerst zu beenden nimmt dem Backend die Quelle neuer Auftraege --
#     sonst schickt die noch laufende Oberflaeche waehrend des Herunterfahrens
#     weitere Anfragen, oder sie meldet dem Benutzer einen Verbindungsabbruch,
#     den in Wahrheit die Paketinstallation ausgeloest hat.
#   * cernis-backend als naechstes: es steuert den Sniff-Helfer. Beendet man
#     den Helfer zuerst, laeuft ein noch aktiver Mitschnitt im Backend auf
#     einen wegbrechenden Helfer und wird als Fehler gemeldet statt als
#     regulaeres Ende.
#   * cernis-sniffd zuletzt: nichts haengt mehr an ihm, er kann seinen
#     Mitschnitt sauber abschliessen.
# Umgekehrt herum entstuende bei jedem Schritt eine Fehlermeldung ueber einen
# Gespraechspartner, der schon weg ist.
#
# BEFUND S85-A5/1 -- DIE KENNUNG KANN NEU VERGEBEN SEIN: die Kennungen werden
# EINMAL ermittelt, danach wird bis zu zehn Sekunden gewartet. Endet unser
# Prozess frueh und vergibt der Kernel die Nummer neu, zeigt sie auf einen
# fremden Prozessbaum. Frueher pruefte das Warten mit "kill -0" nur, ob die
# Nummer VERGEBEN ist; die neue, fremde Nummer galt damit als "laeuft noch",
# und SIGTERM wie SIGKILL trafen den Fremden. Das Skript laeuft als Verwalter,
# also mit dem Recht, jeden beliebigen Prozess zu erschlagen.
# Abhilfe: vor JEDEM Signal und in JEDEM Warteschritt wird ueber
# _cernis_ist_unseres neu gefragt, ob die Kennung noch zu unserem Programm
# gehoert. Eine neu vergebene Nummer gilt als beendet, nicht als laufend.
#
# VERBLEIBENDE RESTLUECKE, ausdruecklich benannt: zwischen der Pruefung und dem
# darauf folgenden "kill" liegt ein Zeitfenster von wenigen Mikrosekunden. Endet
# unser Prozess genau darin und wird die Nummer genau darin neu vergeben, geht
# das Signal doch an den Fremden. Diese Luecke ist in einer POSIX-Shell nicht
# schliessbar: es gibt kein WNOWAIT, keinen pidfd und keine Moeglichkeit,
# Pruefung und Signal in einem Schritt auszufuehren. Sie wird hier von zehn
# Sekunden auf wenige Mikrosekunden verkleinert, nicht beseitigt. Wer sie
# beseitigen will, braucht pidfd_open/pidfd_send_signal -- also ein Programm,
# kein Betreuerskript.
_cernis_beende_programme() {
    for _programm in ${_CERNIS_PROGRAMME}; do
        _pids=$(_cernis_pids_von "${_programm}")
        [ -n "${_pids}" ] || continue

        # Schritt 1: geordnet bitten -- aber nur, was in diesem Augenblick noch
        # unseres ist.
        for _pid in ${_pids}; do
            if _cernis_ist_unseres "${_pid}" "${_programm}"; then
                kill -TERM "${_pid}" 2>/dev/null || true
            fi
        done

        # Schritt 2: auf das TATSAECHLICHE Ende warten, in Zehntelsekunden
        # gepollt. Kein pauschales sleep -- ist der Prozess nach 200 ms weg,
        # geht es nach 200 ms weiter. Massstab ist die Zugehoerigkeit, nicht
        # die blosse Existenz der Nummer.
        _wartend=0
        while [ "${_wartend}" -lt "${_CERNIS_FRIST_ZEHNTEL}" ]; do
            _offen=''
            for _pid in ${_pids}; do
                if _cernis_ist_unseres "${_pid}" "${_programm}"; then
                    _offen="${_offen} ${_pid}"
                fi
            done
            [ -n "${_offen}" ] || break
            sleep 0.1
            _wartend=$((_wartend + 1))
        done

        # Schritt 3: nur was die Frist nicht genutzt hat UND noch unseres ist,
        # wird hart beendet -- und das wird benannt, nicht verschwiegen.
        for _pid in ${_pids}; do
            if _cernis_ist_unseres "${_pid}" "${_programm}"; then
                echo "CERNIS PRO: ${_programm} (PID ${_pid}) hat sich in" \
                     "$((_CERNIS_FRIST_ZEHNTEL / 10)) Sekunden nicht beendet und wird" \
                     "jetzt hart beendet." >&2
                kill -KILL "${_pid}" 2>/dev/null || true
            elif kill -0 "${_pid}" 2>/dev/null; then
                # Die Nummer ist vergeben, gehoert aber nicht mehr uns. Das wird
                # GEMELDET und nicht stillschweigend uebergangen: hier stand das
                # Skript unmittelbar davor, einen fremden Prozessbaum zu
                # erschlagen, und der Verwalter soll erfahren, dass dieser Fall
                # auf seiner Maschine wirklich eintritt. Kein Fehler, keine
                # Abbruchbedingung -- die Installation laeuft weiter, denn unser
                # Prozess IST beendet, und genau das war das Ziel.
                echo "CERNIS PRO: PID ${_pid} gehoerte zu ${_programm}, ist aber" \
                     "inzwischen neu vergeben. Es geht kein Signal an diese PID." >&2
            fi
        done
    done
}

_cernis_beende_programme

exit 0
