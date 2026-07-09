#!/bin/bash
# ============================================================
#  CERNIS PRO - Linux Build Script (Ubuntu / Linux x86_64)
#  Ergebnis: .deb + .AppImage (Version aus tauri.conf.json)
#  Baut BEIDE Binaries (cernis-backend + cernis-sniffd, ADR 0041)
#  gegen den venv-Python und bundelt via Tauri.
#  Aufruf: bash build-linux.sh
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
TAURI_SRC="$SCRIPT_DIR/src-tauri"
TRIPLE="${CERNIS_BUILD_TRIPLE:-x86_64-unknown-linux-gnu}"

# PyInstaller/altgraph zeigt bei der scapy-Modulanalyse einen nicht-
# deterministischen Fehler ("Graph object does not support item assignment");
# ein erneuter Lauf geht in aller Regel durch. Darum jeden pyinstaller-Aufruf
# bis zu 3-mal versuchen. Schlaegt der dritte Versuch fehl, bricht das Skript
# mit Fehler ab (kein stiller Erfolg).
run_pyinstaller_retry() {
    local spec="$1" out="$2"
    local attempt
    for attempt in 1 2 3; do
        echo "      PyInstaller-Versuch $attempt/3: $spec"
        if pyinstaller "$spec" --noconfirm && [ -f "$out" ]; then
            return 0
        fi
        echo "      Versuch $attempt fehlgeschlagen."
    done
    echo "FEHLER: PyInstaller ($spec) nach 3 Versuchen fehlgeschlagen"
    return 1
}

echo "============================================"
echo " CERNIS PRO Linux x86_64 Build"
echo " Ziel-Triple: $TRIPLE"
echo "============================================"

echo ""
echo "[0/6] System-Abhaengigkeiten pruefen..."
MISSING=()
for cmd in nmap setcap; do
    if command -v "$cmd" &>/dev/null; then echo "      $cmd: OK"; else MISSING+=("$cmd"); fi
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "      FEHLT: ${MISSING[*]}"
    echo "      Bitte:  sudo apt install nmap libcap2-bin"
    exit 1
fi

VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then echo "FEHLER: .venv fehlt. Erst 'uv sync'."; exit 1; fi
source "$VENV_DIR/bin/activate"
echo "      Python venv: $(python3 --version)"
if ! python3 -c "import PyInstaller" &>/dev/null; then
    echo "      PyInstaller fehlt:  uv add --dev pyinstaller"; exit 1
fi

echo ""
echo "[1/6] Frontend bauen..."
cd "$FRONTEND_DIR"
npm install --silent
npm run build
echo "      OK"

echo ""
echo "[2/6] Backend-Binary (cernis-backend)..."
cd "$BACKEND_DIR"
rm -rf dist/ build/
run_pyinstaller_retry cernis_linux.spec "$BACKEND_DIR/dist/cernis-backend"
[ -f "$BACKEND_DIR/dist/cernis-backend" ] || { echo "FEHLER: cernis-backend fehlt"; exit 1; }
echo "      OK"

echo ""
echo "[3/6] Sniff-Helfer-Binary (cernis-sniffd)..."
cd "$BACKEND_DIR"
SNIFFD_BIN="$BACKEND_DIR/dist/cernis-sniffd"
run_pyinstaller_retry cernis_sniffd_linux.spec "$SNIFFD_BIN"
[ -f "$SNIFFD_BIN" ] || { echo "FEHLER: cernis-sniffd fehlt"; exit 1; }
echo "      OK"

echo ""
echo "[3b] Sniff-Helfer verifizieren (keine Backend-only-Deps)..."
LEAK=0
for forbidden in fastapi uvicorn starlette reportlab; do
    if strings "$SNIFFD_BIN" | grep -qi "$forbidden"; then
        echo "      WARNUNG: '$forbidden' im sniffd-Binary"; LEAK=1
    fi
done
[ "$LEAK" -eq 0 ] && echo "      OK - schlank"

echo ""
echo "[4/6] Binaries fuer Tauri bereitstellen (Triple $TRIPLE)..."
cp "$BACKEND_DIR/dist/cernis-backend" "$TAURI_SRC/cernis-backend-$TRIPLE"
cp "$SNIFFD_BIN" "$TAURI_SRC/cernis-sniffd-$TRIPLE"
chmod +x "$TAURI_SRC/cernis-backend-$TRIPLE" "$TAURI_SRC/cernis-sniffd-$TRIPLE"
TAURI_RELEASE="$TAURI_SRC/target/$TRIPLE/release"
mkdir -p "$TAURI_RELEASE"
cp "$BACKEND_DIR/dist/cernis-backend" "$TAURI_RELEASE/cernis-backend"
cp "$SNIFFD_BIN" "$TAURI_RELEASE/cernis-sniffd"
chmod +x "$TAURI_RELEASE/cernis-backend" "$TAURI_RELEASE/cernis-sniffd"
echo "      OK"

echo ""
echo "[5/6] Tauri-Build (deb + AppImage)..."
cd "$SCRIPT_DIR"
npm install --silent
# linuxdeploy und appimagetool brauchen sonst FUSE, das in Containern/CI nicht
# verfuegbar ist; mit dieser Variable entpacken sie sich selbst statt zu mounten.
export APPIMAGE_EXTRACT_AND_RUN=1
npx tauri build --target "$TRIPLE"

echo ""
echo "[6/6] Pakete einsammeln..."
VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="$HOME/Desktop"; mkdir -p "$DEST"
BUNDLE_DIR="$TAURI_SRC/target/$TRIPLE/release/bundle"
DEB=$(find "$BUNDLE_DIR/deb" -name "*.deb" -print -quit 2>/dev/null || true)
APPIMAGE=$(find "$BUNDLE_DIR/appimage" -name "*.AppImage" -print -quit 2>/dev/null || true)
[ -n "$DEB" ] && cp "$DEB" "$DEST/cernis-pro_${VERSION}_amd64.deb" && echo "      -> $DEST/cernis-pro_${VERSION}_amd64.deb"
[ -n "$APPIMAGE" ] && cp "$APPIMAGE" "$DEST/cernis-pro_${VERSION}_amd64.AppImage" && echo "      -> $DEST/cernis-pro_${VERSION}_amd64.AppImage"

echo ""
echo "============================================"
echo " BUILD ABGESCHLOSSEN (Version $VERSION)"
echo "============================================"
echo "Hinweis: deb-postinst.sh setzt nach Installation automatisch"
echo "  setcap cap_net_raw+eip /usr/bin/cernis-sniffd"
