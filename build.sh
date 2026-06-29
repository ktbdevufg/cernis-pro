#!/bin/bash
# ============================================================
#  CERNIS PRO – macOS Build Script
#  Plattform: macOS ARM64 (Apple Silicon)
#  Ergebnis:  cernis-pro_1.0.0_aarch64.dmg
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
echo " CERNIS PRO macOS ARM64 Build"
echo " Arbeitsverzeichnis: $SCRIPT_DIR"
echo "============================================"

# ── Schritt 0: System-Abhängigkeiten prüfen ──────────────────
echo ""
echo "[0/5] System-Abhängigkeiten prüfen..."

# brew-Pakete
BREW_MISSING=()
for pkg in nmap libpcap; do
    if brew list "$pkg" &>/dev/null; then
        echo "      $pkg: OK"
    else
        BREW_MISSING+=("$pkg")
    fi
done
if [ ${#BREW_MISSING[@]} -gt 0 ]; then
    echo "      Installiere fehlende brew-Pakete: ${BREW_MISSING[*]}"
    brew install "${BREW_MISSING[@]}"
fi

# ── Python venv erstellen/aktivieren ─────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "      Python venv erstellen..."
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
echo "      Python venv: $VENV_DIR ($(python3 --version))"

# PyInstaller installieren
if ! command -v pyinstaller &>/dev/null; then
    echo "      PyInstaller installieren..."
    pip3 install pyinstaller --quiet
fi

# pip3-Pakete (innerhalb venv)
for pymod in scapy pysnmp reportlab dnspython; do
    if python3 -c "import $pymod" &>/dev/null; then
        echo "      $pymod: OK"
    else
        echo "      $pymod nicht gefunden — installiere via pip3..."
        pip3 install "$pymod" --quiet
    fi
done

# ── Schritt 1: Python-Abhängigkeiten installieren ────────────
echo ""
echo "[1/5] Python-Abhängigkeiten installieren..."
cd "$BACKEND_DIR"
pip3 install -r requirements.txt --quiet
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

pyinstaller cernis_macos.spec --noconfirm

BACKEND_BIN="$BACKEND_DIR/dist/cernis-backend"
if [ ! -f "$BACKEND_BIN" ]; then
    echo "FEHLER: cernis-backend Binary nicht gefunden!"
    exit 1
fi
echo "      OK — $BACKEND_BIN"

# ── Schritt 4: Binary für Tauri-Bundler bereitstellen ─────────
echo ""
echo "[4/5] Backend Binary für Tauri bereitstellen..."

# Tauri externalBin erwartet: cernis-backend-aarch64-apple-darwin
TAURI_BIN_NAME="cernis-backend-aarch64-apple-darwin"
cp "$BACKEND_BIN" "$TAURI_SRC/$TAURI_BIN_NAME"
chmod +x "$TAURI_SRC/$TAURI_BIN_NAME"

# Auch in target/aarch64-apple-darwin/release/ ablegen
TAURI_RELEASE="$TAURI_DIR/src-tauri/target/aarch64-apple-darwin/release"
mkdir -p "$TAURI_RELEASE"
cp "$BACKEND_BIN" "$TAURI_RELEASE/cernis-backend"
chmod +x "$TAURI_RELEASE/cernis-backend"

echo "      OK"

# ── Schritt 4b: Sniff-Helfer (cernis-sniffd, ADR 0041) ───────
echo ""
echo "[4b] Sniff-Helfer Binary erstellen und bereitstellen (cernis-sniffd)..."
cd "$BACKEND_DIR"

# dist/ NICHT erneut loeschen: enthaelt bereits cernis-backend aus Schritt 3.
pyinstaller cernis_sniffd_macos.spec --noconfirm

SNIFFD_BIN="$BACKEND_DIR/dist/cernis-sniffd"
if [ ! -f "$SNIFFD_BIN" ]; then
    echo "FEHLER: cernis-sniffd Binary nicht gefunden!"
    exit 1
fi
echo "      OK — $SNIFFD_BIN"

# Tauri externalBin erwartet: cernis-sniffd-aarch64-apple-darwin
SNIFFD_BIN_NAME="cernis-sniffd-aarch64-apple-darwin"
cp "$SNIFFD_BIN" "$TAURI_SRC/$SNIFFD_BIN_NAME"
chmod +x "$TAURI_SRC/$SNIFFD_BIN_NAME"

# Auch ins selbe Release-Verzeichnis wie das Backend ablegen
cp "$SNIFFD_BIN" "$TAURI_RELEASE/cernis-sniffd"
chmod +x "$TAURI_RELEASE/cernis-sniffd"

echo "      OK"

# ── Schritt 5: Tauri bauen ────────────────────────────────────
echo ""
echo "[5/5] Tauri Build (.dmg)..."
cd "$TAURI_DIR"
npm install --silent
npm run build-tauri

# ── Schritt 6: Pakete nach Desktop kopieren ──────────────────
echo ""
echo "[6] Pakete kopieren..."

VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="$HOME/Desktop"
mkdir -p "$DEST"

DMG=$(find "$TAURI_DIR/src-tauri/target" -name "*.dmg" -print -quit 2>/dev/null)

if [ -n "$DMG" ]; then
    cp "$DMG" "$DEST/cernis-pro_${VERSION}_aarch64.dmg"
    echo "      → $DEST/cernis-pro_${VERSION}_aarch64.dmg"
fi

echo ""
echo "============================================"
echo " BUILD ERFOLGREICH"
echo "============================================"
echo ""
echo "Pakete:"
[ -n "$DMG" ] && echo "  $DEST/cernis-pro_${VERSION}_aarch64.dmg"
echo ""
