#!/bin/bash
# ============================================================
#  CERNIS PRO – Linux Build Script
#  Plattform: Ubuntu 24.04 LTS x64
#  Ergebnis:  cernis-pro_1.0.0_amd64.deb
#             cernis-pro_1.0.0_amd64.AppImage
#
#  Aufruf: bash build.sh
# ============================================================

set -e  # Bei Fehler sofort abbrechen

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
TAURI_DIR="$SCRIPT_DIR"
TAURI_SRC="$SCRIPT_DIR/src-tauri"

echo "============================================"
echo " CERNIS PRO Linux Build"
echo " Arbeitsverzeichnis: $SCRIPT_DIR"
echo "============================================"

# ── Schritt 0: System-Abhängigkeiten prüfen ──────────────────
echo ""
echo "[0/5] System-Abhängigkeiten prüfen..."

# apt-Pakete
APT_MISSING=()
for pkg in nmap libpcap-dev net-tools traceroute; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "      $pkg: OK"
    else
        APT_MISSING+=("$pkg")
    fi
done
if [ ${#APT_MISSING[@]} -gt 0 ]; then
    echo "      Installiere fehlende apt-Pakete: ${APT_MISSING[*]}"
    sudo apt-get update -qq && sudo apt-get install -y "${APT_MISSING[@]}"
fi

# pip3-Pakete
for pymod in scapy pysnmp reportlab dnspython; do
    if python3 -c "import $pymod" &>/dev/null; then
        echo "      $pymod: OK"
    else
        echo "      $pymod nicht gefunden — installiere via pip3..."
        pip3 install "$pymod" --break-system-packages --quiet
    fi
done

# ── Schritt 1: Python-Abhängigkeiten installieren ────────────
echo ""
echo "[1/5] Python-Abhängigkeiten installieren..."
cd "$BACKEND_DIR"
pip3 install -r requirements.txt --break-system-packages --quiet
echo "      OK"

# ── Schritt 2: Frontend bauen ─────────────────────────────────
echo ""
echo "[2/5] Frontend bauen (npm)..."
cd "$FRONTEND_DIR"
npm install --silent
npm run build
echo "      OK — dist/ erstellt"

# ── Schritt 3: PyInstaller — Backend Binary erstellen ─────────
echo ""
echo "[3/5] Backend Binary erstellen (PyInstaller)..."
cd "$BACKEND_DIR"

# Altes Build-Verzeichnis aufräumen
rm -rf dist/ build/

pyinstaller cernis_linux.spec --noconfirm

BACKEND_BIN="$BACKEND_DIR/dist/cernis-backend"
if [ ! -f "$BACKEND_BIN" ]; then
    echo "FEHLER: cernis-backend Binary nicht gefunden!"
    exit 1
fi
echo "      OK — $BACKEND_BIN"

# ── Schritt 4: Binary für Tauri-Bundler bereitstellen ─────────
echo ""
echo "[4/5] Backend Binary für Tauri bereitstellen..."

# Tauri externalBin erwartet: cernis-backend-x86_64-unknown-linux-gnu
TAURI_BIN_NAME="cernis-backend-x86_64-unknown-linux-gnu"
cp "$BACKEND_BIN" "$TAURI_SRC/$TAURI_BIN_NAME"
chmod +x "$TAURI_SRC/$TAURI_BIN_NAME"

# Auch in target/x86_64-unknown-linux-gnu/release/ ablegen
TAURI_RELEASE="$TAURI_DIR/src-tauri/target/x86_64-unknown-linux-gnu/release"
mkdir -p "$TAURI_RELEASE"
cp "$BACKEND_BIN" "$TAURI_RELEASE/cernis-backend"
chmod +x "$TAURI_RELEASE/cernis-backend"

echo "      OK"

# ── Schritt 5: Tauri bauen ────────────────────────────────────
echo ""
echo "[5/5] Tauri Build (.deb + .AppImage)..."
cd "$TAURI_DIR"
npm install --silent
npm run build-tauri

# ── Schritt 6: Pakete nach /home/kbach/ kopieren ─────────────
echo ""
echo "[6] Pakete kopieren..."

VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="/home/kbach"
mkdir -p "$DEST"

DEB=$(find "$TAURI_DIR/src-tauri/target" -name "*.deb" -print -quit 2>/dev/null)
APPIMAGE=$(find "$TAURI_DIR/src-tauri/target" -name "*.AppImage" -print -quit 2>/dev/null)

if [ -n "$DEB" ]; then
    cp "$DEB" "$DEST/cernis-pro_${VERSION}_amd64.deb"
    echo "      → $DEST/cernis-pro_${VERSION}_amd64.deb"
fi
if [ -n "$APPIMAGE" ]; then
    cp "$APPIMAGE" "$DEST/cernis-pro_${VERSION}_amd64.AppImage"
    chmod +x "$DEST/cernis-pro_${VERSION}_amd64.AppImage"
    echo "      → $DEST/cernis-pro_${VERSION}_amd64.AppImage"
fi

echo ""
echo "============================================"
echo " BUILD ERFOLGREICH"
echo "============================================"
echo ""
echo "Pakete:"
[ -n "$DEB" ]      && echo "  $DEST/cernis-pro_${VERSION}_amd64.deb"
[ -n "$APPIMAGE" ] && echo "  $DEST/cernis-pro_${VERSION}_amd64.AppImage"
echo ""
