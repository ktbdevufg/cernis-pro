#!/bin/bash
# ============================================================
#  CERNIS PRO 2.0 - Widerruf des BPF-Zugriffs (macOS)
# ============================================================
# Nimmt zurueck, was scripts/setup-bpf-access.sh eingerichtet hat. Gegenstueck zu
# jenem Skript in Stil, Fehlerbehandlung und Idempotenz - bewusst als EIGENE Datei
# und nicht als zweiter Modus des Setup-Skripts: das Einrichten und das Abraeumen
# sind zwei verschiedene Operationen mit verschiedenen Vorbedingungen.
#
# Aufruf (durch den macOS-Adapter, via osascript mit Administratorrechten):
#   sudo bash revoke-bpf-access.sh <benutzername> <modus>
#
# Der Benutzername wird UEBERGEBEN und nicht geraten: unter sudo ist $USER root,
# die Mitgliedschaft betrifft aber den aufrufenden Nutzer.
#
# ZWEI MODI - und warum es sie geben MUSS:
#   mitgliedschaft  Entfernt NUR die Gruppenmitgliedschaft des genannten Nutzers.
#                   Gruppe, Systemdienst, Helfer und Geraeterechte bleiben stehen.
#   vollstaendig    Raeumt alles ab und setzt die Geraeterechte auf den
#                   Auslieferungszustand root:wheel 0600 zurueck.
#
# Die BPF-Geraete und der LaunchDaemon sind SYSTEMWEITE Ressourcen: alle macOS-Konten
# der Maschine teilen sie sich. Ein blindes vollstaendiges Abraeumen wuerde darum den
# uebrigen Mitgliedern der Gruppe cernis-capture den Zugriff nehmen, ohne dass sie
# gefragt worden waeren. Welcher Modus gilt, entscheidet deshalb der Nutzer in der
# Oberflaeche (er sieht dort die uebrigen Mitglieder), nicht dieses Skript.
#
# Das Skript ist IDEMPOTENT: mehrfacher Aufruf ist unschaedlich. "War nicht
# vorhanden" ist sachlich KEIN Fehler und endet mit Exit 0; ein echter Fehlschlag
# (etwas ist da, laesst sich aber nicht entfernen) bricht dagegen hart ab
# (S3: kein stiller Fallback, kein "|| true" auf echten Fehlern).
# ============================================================
set -euo pipefail

GRUPPE="cernis-capture"
HELFER_PFAD="/usr/local/bin/cernis-bpf-access.sh"
PLIST_LABEL="de.cernis.capture"
PLIST_PFAD="/Library/LaunchDaemons/${PLIST_LABEL}.plist"

# Fehlerausgang: Meldung auf stderr, Exit != 0. Wie im Setup-Skript an allen
# Pruefpunkten genutzt, damit ein Fehlschlag NIE als Erfolg durchgeht.
fehler() {
    echo "FEHLER: $*" >&2
    exit 1
}

# ── Vorbedingungen ───────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    fehler "Dieses Skript muss mit Administratorrechten laufen (erwartet: root)."
fi

if [ "$#" -ne 2 ]; then
    fehler "Genau zwei Argumente erwartet: <benutzername> <modus>, Modus ist 'mitgliedschaft' oder 'vollstaendig'."
fi

BENUTZER="$1"
MODUS="$2"

# Wie beim Setup: ein Tippfehler im Namen darf nicht still nichts bewirken und
# trotzdem als "widerrufen" gelten.
if ! id -u -- "${BENUTZER}" >/dev/null 2>&1; then
    fehler "Unbekannter Benutzer '${BENUTZER}' - keine Aenderung vorgenommen."
fi

if [ "${MODUS}" != "mitgliedschaft" ] && [ "${MODUS}" != "vollstaendig" ]; then
    fehler "Unbekannter Modus '${MODUS}' - erlaubt sind 'mitgliedschaft' und 'vollstaendig'."
fi

# ── Modus 'mitgliedschaft': nur den eigenen Zugang zuruecknehmen ─
# Der schonende Weg. Alles Systemweite bleibt unangetastet, die uebrigen Mitglieder
# behalten ihren Zugriff.
if [ "${MODUS}" = "mitgliedschaft" ]; then
    if ! dseditgroup -o read "${GRUPPE}" >/dev/null 2>&1; then
        # Keine Gruppe, also auch keine Mitgliedschaft - der gewuenschte Endzustand
        # liegt bereits vor. Idempotenz, kein Fehler.
        echo "Gruppe '${GRUPPE}' existiert nicht - es gibt keine Mitgliedschaft zu entfernen."
        exit 0
    fi

    if ! dseditgroup -o checkmember -m "${BENUTZER}" "${GRUPPE}" >/dev/null 2>&1; then
        echo "Benutzer '${BENUTZER}' ist kein Mitglied von '${GRUPPE}' - nichts zu tun."
        exit 0
    fi

    dseditgroup -o edit -d "${BENUTZER}" -t user "${GRUPPE}" \
        || fehler "Benutzer '${BENUTZER}' konnte nicht aus '${GRUPPE}' entfernt werden."
    echo "Benutzer '${BENUTZER}' aus '${GRUPPE}' entfernt."

    echo ""
    echo "Widerruf abgeschlossen (nur Mitgliedschaft)."
    echo "  Entfernt:    Mitgliedschaft von '${BENUTZER}' in '${GRUPPE}'"
    echo "  Unberuehrt:  Gruppe, Helferskript, LaunchDaemon, Geraeterechte"
    echo ""
    echo "Hinweis: Der Entzug greift fuer bereits laufende Programme erst nach einer"
    echo "neuen Anmeldung."
    exit 0
fi

# ── Modus 'vollstaendig': die gesamte Einrichtung abraeumen ───
# Reihenfolge ist bewusst umgekehrt zur Einrichtung: erst den Dienst stoppen, dann
# seine Dateien entfernen, dann die Gruppe, zuletzt die Geraeterechte. Wuerde die
# Gruppe zuerst fallen, koennte ein noch laufender Helfer sie nicht mehr finden.

# ── a) LaunchDaemon entladen ─────────────────────────────────
# NUR hier ist Fehlertoleranz sachlich richtig: "war nicht geladen" ist kein Fehler
# und laesst sich von launchctl nicht zuverlaessig von echten Fehlern unterscheiden.
launchctl bootout "system/${PLIST_LABEL}" >/dev/null 2>&1 || true
echo "LaunchDaemon '${PLIST_LABEL}' entladen (sofern er geladen war)."

# ── b) plist loeschen ────────────────────────────────────────
if [ -e "${PLIST_PFAD}" ]; then
    rm -f "${PLIST_PFAD}" || fehler "LaunchDaemon-plist konnte nicht geloescht werden: ${PLIST_PFAD}"
    echo "LaunchDaemon-plist geloescht: ${PLIST_PFAD}"
else
    echo "LaunchDaemon-plist war nicht vorhanden: ${PLIST_PFAD}"
fi

# ── c) Helferskript loeschen ─────────────────────────────────
if [ -e "${HELFER_PFAD}" ]; then
    rm -f "${HELFER_PFAD}" || fehler "Helferskript konnte nicht geloescht werden: ${HELFER_PFAD}"
    echo "Helferskript geloescht: ${HELFER_PFAD}"
else
    echo "Helferskript war nicht vorhanden: ${HELFER_PFAD}"
fi

# ── d) Gruppe loeschen ───────────────────────────────────────
# Mit der Gruppe verschwinden alle Mitgliedschaften - genau das ist im vollstaendigen
# Modus gewollt und wurde in der Oberflaeche angekuendigt.
if dseditgroup -o read "${GRUPPE}" >/dev/null 2>&1; then
    dseditgroup -o delete "${GRUPPE}" || fehler "Gruppe '${GRUPPE}' konnte nicht geloescht werden."
    echo "Gruppe '${GRUPPE}' geloescht."
else
    echo "Gruppe '${GRUPPE}' war nicht vorhanden."
fi

# ── e) Geraeterechte zuruecksetzen ───────────────────────────
# Auslieferungszustand von macOS: root:wheel mit 0600. Ohne diesen Schritt blieben
# die Geraete der geloeschten Gruppen-ID zugeordnet und mit g+rw versehen - eine
# spaeter neu angelegte Gruppe koennte dieselbe ID bekommen und den Zugriff erben.
# nullglob wie im Setup-Helfer: ohne es wuerde das unexpandierte Muster '/dev/bpf*'
# als Dateiname an chown durchgereicht.
shopt -s nullglob
GERAETE=(/dev/bpf*)
if [ "${#GERAETE[@]}" -eq 0 ]; then
    # Auf einer Maschine, die noch nie einen Mitschnitt gemacht hat, kann es sie
    # nicht geben - kein Fehler.
    echo "Keine BPF-Geraete unter /dev/bpf* vorhanden - Rechte muessen nicht zurueckgesetzt werden."
else
    chown root:wheel "${GERAETE[@]}" || fehler "Eigentuemer der BPF-Geraete nicht zuruecksetzbar."
    chmod 0600 "${GERAETE[@]}" || fehler "Rechte der BPF-Geraete nicht zuruecksetzbar."
    echo "Rechte von ${#GERAETE[@]} BPF-Geraet(en) auf root:wheel 0600 zurueckgesetzt."
fi

echo ""
echo "BPF-Zugriff vollstaendig widerrufen."
echo "  Gruppe:        ${GRUPPE} (geloescht, damit alle Mitgliedschaften)"
echo "  Helferskript:  ${HELFER_PFAD} (geloescht)"
echo "  LaunchDaemon:  ${PLIST_PFAD} (entladen und geloescht)"
echo "  Geraeterechte: /dev/bpf* zurueck auf root:wheel 0600"
echo ""
echo "Hinweis: Fuer bereits laufende Programme greift der Entzug der Gruppenrechte"
echo "erst nach einer neuen Anmeldung. Die Geraeterechte gelten ab sofort."
