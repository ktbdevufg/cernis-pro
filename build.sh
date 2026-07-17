#!/bin/bash
# ============================================================
#  CERNIS PRO - macOS Build Script (macOS ARM64 / Apple Silicon)
#  Ergebnis: .dmg (Version aus tauri.conf.json)
#  Baut BEIDE Binaries (cernis-backend + cernis-sniffd, ADR 0041)
#  gegen den venv-Python und bundelt via Tauri.
#  Aufruf: bash build.sh
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
TAURI_SRC="$SCRIPT_DIR/src-tauri"
TRIPLE="${CERNIS_BUILD_TRIPLE:-aarch64-apple-darwin}"

echo "============================================"
echo " CERNIS PRO macOS ARM64 (Apple Silicon) Build"
echo " Ziel-Triple: $TRIPLE"
echo "============================================"

echo ""
echo "[0/6] System-Abhaengigkeiten pruefen..."
MISSING=()
for cmd in nmap; do
    if command -v "$cmd" &>/dev/null; then echo "      $cmd: OK"; else MISSING+=("$cmd"); fi
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "      FEHLT: ${MISSING[*]}"
    echo "      Bitte:  brew install nmap"
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
echo "[0b/6] Build-Version erzeugen (_build_version.py)..."
SHORT_SHA=$(git rev-parse --short=7 HEAD)
BUILD_VERSION="2.0.0+macos.${SHORT_SHA}"
cat > "$BACKEND_DIR/infrastructure/_build_version.py" << EOF
"""Im CI erzeugte Build-Version. Nicht committet (siehe .gitignore)."""
BUILD_VERSION = "${BUILD_VERSION}"
EOF
echo "      Build-Version: ${BUILD_VERSION}"

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
pyinstaller cernis_macos.spec --noconfirm
[ -f "$BACKEND_DIR/dist/cernis-backend" ] || { echo "FEHLER: cernis-backend fehlt"; exit 1; }
echo "      OK"

echo ""
echo "[3/6] Sniff-Helfer-Binary (cernis-sniffd)..."
cd "$BACKEND_DIR"
SNIFFD_BIN="$BACKEND_DIR/dist/cernis-sniffd"
pyinstaller cernis_sniffd_macos.spec --noconfirm
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
echo "[5/6] Tauri-Build (.dmg)..."
cd "$SCRIPT_DIR"
npm install --silent
npx tauri build --target "$TRIPLE"

echo ""
echo "[6/6] Pakete einsammeln..."
VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="$HOME/Desktop"; mkdir -p "$DEST"
BUNDLE_DIR="$TAURI_SRC/target/$TRIPLE/release/bundle"
DMG=$(find "$BUNDLE_DIR/dmg" -name "*.dmg" -print -quit 2>/dev/null || true)
[ -n "$DMG" ] && cp "$DMG" "$DEST/cernis-pro_${VERSION}_aarch64.dmg" && echo "      -> $DEST/cernis-pro_${VERSION}_aarch64.dmg"

echo ""
echo "============================================"
echo " BUILD ABGESCHLOSSEN (Version $VERSION)"
echo "============================================"
echo "Hinweis: Rechte-Strategie fuer cernis-sniffd (Sniff-Features) folgt separat (Option A,"
echo "  SMJobBless/LaunchDaemon) — der rootlose Kern laeuft ohne Zusatzrechte."
