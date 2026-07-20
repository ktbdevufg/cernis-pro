#!/bin/bash
# ============================================================
#  CERNIS PRO 2.0 - Einrichtung des BPF-Zugriffs (macOS)
# ============================================================
# Richtet den Zugriff auf die BPF-Geraeteknoten /dev/bpf* fuer die Sniff-Familie
# (SNI, pcap, LLDP, DNS) ein, damit KEIN CERNIS-Prozess als root laufen muss.
#
# Aufruf (durch den macOS-Adapter, via osascript mit Administratorrechten):
#   sudo bash setup-bpf-access.sh <benutzername>
#
# Der Benutzername wird als Argument UEBERGEBEN und nicht geraten: unter sudo ist
# $USER root, die Gruppenmitgliedschaft muss aber der aufrufende Nutzer bekommen.
#
# NEUFASSUNG nach v2-Regeln, bewusst NICHT abgeleitet vom v1-Skript
# scripts/install-bpf-permissions.sh. Zwei harte Unterschiede:
#   1. Rechte-Modell: chgrp auf eine EIGENE Gruppe (cernis-capture) + chmod g+rw.
#      Das v1-Skript setzte chmod o+rw und oeffnete die Geraete damit fuer JEDEN
#      Prozess JEDES Nutzers der Maschine (Mitlesen des gesamten Netzverkehrs).
#      Der Unterschied bleibt o+rw vs. g+rw: NUR die Gruppe darf, nicht jeder.
#   2. Fehlerbehandlung: KEIN "|| true" auf sicherheitsrelevanten Schritten. Jeder
#      fehlgeschlagene Schritt bricht mit Exit-Code != 0 und klarer stderr-Meldung
#      ab (S3: kein stiller Fallback auf unsicheres Verhalten).
#
# Das Skript ist IDEMPOTENT: mehrfacher Aufruf ist unschaedlich (Gruppe/Nutzer/
# Helfer/LaunchDaemon werden nur angelegt bzw. ueberschrieben, nie dupliziert).
# ============================================================
set -euo pipefail

GRUPPE="cernis-capture"
# Feste GID der Capture-Gruppe (Begruendung der Wahl bei der Anlage in Abschnitt a).
GRUPPE_GID="447"
HELFER_PFAD="/usr/local/bin/cernis-bpf-access.sh"
PLIST_LABEL="de.cernis.capture"
PLIST_PFAD="/Library/LaunchDaemons/${PLIST_LABEL}.plist"

# Fehlerausgang: Meldung auf stderr, Exit != 0. Wird an allen Pruefpunkten genutzt,
# damit ein Fehlschlag NIE als Erfolg durchgeht.
fehler() {
    echo "FEHLER: $*" >&2
    exit 1
}

# ── Vorbedingungen ───────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    fehler "Dieses Skript muss mit Administratorrechten laufen (erwartet: root)."
fi

if [ "$#" -ne 1 ]; then
    fehler "Genau ein Argument erwartet: der Benutzername, der Zugriff erhalten soll."
fi

BENUTZER="$1"

# Der uebergebene Name muss ein existierendes Konto sein. Ohne diese Pruefung wuerde
# ein Tippfehler still eine Gruppe ohne Mitglied hinterlassen ("eingerichtet", aber
# wirkungslos) -- genau die Art stiller Fehlschlag, die v2 ausschliesst.
if ! id -u -- "${BENUTZER}" >/dev/null 2>&1; then
    fehler "Unbekannter Benutzer '${BENUTZER}' - keine Aenderung vorgenommen."
fi

# ── a) Gruppe anlegen (idempotent) ───────────────────────────
# dseditgroup -o read liefert != 0, wenn die Gruppe fehlt. Nur dann anlegen.
#
# FESTE GID: ohne -i vergibt dseditgroup eine willkuerliche GID (real beobachtet die 501,
# also die des ersten Benutzerkontos). Das ist unschaedlich -- alles loest ueber den NAMEN
# auf --, aber unsauber. Wir vergeben daher eine feste GID aus dem Bereich 400-499: macOS
# nutzt <400 fuer System-/Apple-Gruppen und laesst 400-499 fuer lokale Drittanbieter-
# Gruppen faktisch frei (die 300er sind teils belegt). 447 ist innerhalb dieses Bereichs
# frei gewaehlt.
#
# S3: die GID wird NICHT blind gesetzt. Ist sie auf dieser Maschine unerwartet schon
# vergeben, wird die Gruppe ehrlich OHNE feste GID angelegt (bisheriges Verhalten) und
# eine Warnung ausgegeben -- ein harter Abbruch waere hier unangemessen, denn die feste
# GID ist Kosmetik, die Funktion haengt allein am Namen.
if dseditgroup -o read "${GRUPPE}" >/dev/null 2>&1; then
    echo "Gruppe '${GRUPPE}' existiert bereits."
else
    # Achtung: 'dscl . -search' liefert auch bei LEEREM Treffer den Exit-Code 0 -- die
    # Belegung muss deshalb an der AUSGABE geprueft werden, nicht am Exit-Code.
    if [ -z "$(dscl . -search /Groups PrimaryGroupID "${GRUPPE_GID}" 2>/dev/null)" ]; then
        dseditgroup -o create -i "${GRUPPE_GID}" -r "CERNIS PRO Packet Capture" "${GRUPPE}" \
            || fehler "Gruppe '${GRUPPE}' konnte nicht angelegt werden."
        echo "Gruppe '${GRUPPE}' angelegt (GID ${GRUPPE_GID})."
    else
        echo "WARNUNG: GID ${GRUPPE_GID} ist auf diesem System bereits vergeben -" >&2
        echo "         '${GRUPPE}' wird ohne feste GID angelegt (Aufloesung ueber den Namen)." >&2
        dseditgroup -o create -r "CERNIS PRO Packet Capture" "${GRUPPE}" \
            || fehler "Gruppe '${GRUPPE}' konnte nicht angelegt werden."
        echo "Gruppe '${GRUPPE}' angelegt (GID automatisch vergeben)."
    fi
fi

# ── b) Aufrufenden Nutzer der Gruppe hinzufuegen (idempotent) ─
# -o checkmember prueft die Mitgliedschaft; -o edit -a fuegt hinzu.
if dseditgroup -o checkmember -m "${BENUTZER}" "${GRUPPE}" >/dev/null 2>&1; then
    echo "Benutzer '${BENUTZER}' ist bereits Mitglied von '${GRUPPE}'."
else
    dseditgroup -o edit -a "${BENUTZER}" -t user "${GRUPPE}" \
        || fehler "Benutzer '${BENUTZER}' konnte '${GRUPPE}' nicht hinzugefuegt werden."
    echo "Benutzer '${BENUTZER}' zu '${GRUPPE}' hinzugefuegt."
fi

# ── c) Helferskript nach /usr/local/bin/ legen ───────────────
# Es weist die BPF-Geraete der Gruppe zu und gibt IHR Lese- und Schreibrechte (g+rw,
# von scapy zwingend gebraucht) -- bewusst NICHT o+rw. /usr/local/bin existiert nicht
# auf jedem System zwingend.
mkdir -p /usr/local/bin || fehler "/usr/local/bin konnte nicht angelegt werden."

# Quoted Heredoc ('HELFER'): der Inhalt wird UNVERAENDERT geschrieben, die Variablen
# darin expandiert erst der Helfer zur Laufzeit (nicht dieses Skript).
cat > "${HELFER_PFAD}" << 'HELFER' || fehler "Helferskript konnte nicht geschrieben werden."
#!/bin/bash
# CERNIS PRO 2.0 - setzt die Rechte der BPF-Geraete (vom LaunchDaemon bei jedem Boot).
# Gruppe cernis-capture erhaelt LESE- UND SCHREIBrechte (g+rw). Schreibrechte sind
# noetig, weil scapy die BPF-Geraete SCHREIBEND oeffnet (Setzen der BPF-Filter per
# ioctl) -- g+r allein genuegt nicht und endet in "Permission denied: could not open
# /dev/bpf0". Referenz: Wiresharks ChmodBPF vergibt seiner Capture-Gruppe ebenfalls rw.
# Bewusst weiterhin kein o+rw: die Geraete bleiben fuer alle uebrigen Nutzer der
# Maschine unzugaenglich.
set -euo pipefail

# Vor dem ersten Zugriff existiert ggf. nur /dev/bpf0; nullglob verhindert, dass das
# unexpandierte Muster als Dateiname durchgereicht wird.
shopt -s nullglob
GERAETE=(/dev/bpf*)
if [ "${#GERAETE[@]}" -eq 0 ]; then
    echo "FEHLER: keine BPF-Geraete unter /dev/bpf* gefunden." >&2
    exit 1
fi

chgrp cernis-capture "${GERAETE[@]}"
chmod g+rw "${GERAETE[@]}"
HELFER

chown root:wheel "${HELFER_PFAD}" || fehler "Eigentuemer des Helferskripts nicht setzbar."
chmod 755 "${HELFER_PFAD}" || fehler "Rechte des Helferskripts nicht setzbar."
echo "Helferskript geschrieben: ${HELFER_PFAD}"

# ── d) LaunchDaemon anlegen (RunAtLoad) ──────────────────────
cat > "${PLIST_PFAD}" << PLIST || fehler "LaunchDaemon-plist konnte nicht geschrieben werden."
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${HELFER_PFAD}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/cernis-bpf-access.log</string>
</dict>
</plist>
PLIST

# Eigentuemer/Rechte des plist: root:wheel, 644. launchd verweigert den Dienst sonst.
chown root:wheel "${PLIST_PFAD}" || fehler "Eigentuemer des plist nicht setzbar."
chmod 644 "${PLIST_PFAD}" || fehler "Rechte des plist nicht setzbar."
echo "LaunchDaemon geschrieben: ${PLIST_PFAD}"

# ── LaunchDaemon aktivieren (idempotent) ─────────────────────
# Ein bereits geladener Dienst wird zuerst entladen, damit die neue Fassung greift.
# NUR hier ist Fehlertoleranz sachlich richtig: "war nicht geladen" ist kein Fehler.
# Der eigentliche Ladeschritt darunter wird dagegen streng geprueft.
launchctl bootout "system/${PLIST_LABEL}" >/dev/null 2>&1 || true

launchctl bootstrap system "${PLIST_PFAD}" \
    || fehler "LaunchDaemon '${PLIST_LABEL}' konnte nicht aktiviert werden."
echo "LaunchDaemon aktiviert: ${PLIST_LABEL}"

# ── e) Rechte sofort setzen (ohne Neustart nutzbar) ──────────
# Der Daemon setzt die Rechte bei jedem Boot; fuer den laufenden Betrieb wird der
# Helfer direkt einmal ausgefuehrt. Schlaegt das fehl, ist die Einrichtung NICHT
# gelungen -- also harter Abbruch statt "klappt nach dem naechsten Neustart".
"${HELFER_PFAD}" || fehler "BPF-Rechte konnten nicht sofort gesetzt werden."

echo ""
echo "BPF-Zugriff eingerichtet."
echo "  Gruppe:        ${GRUPPE} (Mitglied: ${BENUTZER})"
echo "  Helferskript:  ${HELFER_PFAD}"
echo "  LaunchDaemon:  ${PLIST_PFAD}"
echo ""
echo "Hinweis: Die Gruppenmitgliedschaft greift fuer bereits laufende Programme erst"
echo "nach einer neuen Anmeldung. Die Geraeterechte selbst gelten ab sofort."
