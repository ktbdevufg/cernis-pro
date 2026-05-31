#!/bin/bash
# ============================================================
#  CERNIS PRO — BPF Permissions Installer (macOS)
#
#  Erstellt einen LaunchDaemon der bei jedem Boot die
#  /dev/bpf* Permissions setzt, damit Packet Capture ohne
#  sudo funktioniert.
#
#  Aufruf:  sudo bash install-bpf-permissions.sh
#  Deinstallation: sudo bash install-bpf-permissions.sh --uninstall
# ============================================================

set -e

PLIST_NAME="de.cernis.ChmodBPF"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_NAME}.plist"
SCRIPT_PATH="/usr/local/bin/cernis-chmod-bpf.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Fehler: Dieses Script muss mit sudo ausgeführt werden."
    echo "  sudo bash $0"
    exit 1
fi

# ── Uninstall ────────────────────────────────────────────────
if [ "$1" = "--uninstall" ]; then
    echo "Deinstalliere BPF Permissions..."
    launchctl bootout system "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH" "$SCRIPT_PATH"
    echo "Fertig. BPF Permissions werden beim nächsten Boot zurückgesetzt."
    exit 0
fi

# ── Install: Helper Script ───────────────────────────────────
echo "Installiere BPF Permissions für CERNIS PRO..."

cat > "$SCRIPT_PATH" << 'SCRIPT'
#!/bin/bash
# Set read-write permissions on BPF devices for packet capture
chmod o+rw /dev/bpf*
SCRIPT
chmod 755 "$SCRIPT_PATH"

# ── Install: LaunchDaemon ────────────────────────────────────
cat > "$PLIST_PATH" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${SCRIPT_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/cernis-chmod-bpf.log</string>
</dict>
</plist>
PLIST

chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"

# ── Sofort aktivieren ────────────────────────────────────────
launchctl bootstrap system "$PLIST_PATH" 2>/dev/null || launchctl load "$PLIST_PATH" 2>/dev/null || true
# Permissions sofort setzen
"$SCRIPT_PATH"

echo ""
echo "============================================"
echo " BPF Permissions installiert"
echo "============================================"
echo ""
echo " LaunchDaemon: $PLIST_PATH"
echo " Script:       $SCRIPT_PATH"
echo ""
echo " /dev/bpf* Permissions werden bei jedem Boot"
echo " automatisch auf o+rw gesetzt."
echo ""
echo " Packet Capture in CERNIS PRO funktioniert"
echo " jetzt ohne sudo."
echo ""
echo " Deinstallation:"
echo "   sudo bash $0 --uninstall"
echo ""
