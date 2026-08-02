#!/bin/bash
# ============================================================
#  CERNIS PRO - Linux Build Script (Ubuntu / Linux x86_64)
#  Ergebnis: .deb (Version aus tauri.conf.json)
#  Baut BEIDE Binaries (cernis-backend + cernis-sniffd, ADR 0041)
#  gegen den venv-Python und bundelt via Tauri.
#  Kein AppImage: src-tauri/tauri.linux.conf.json ueberschreibt bundle.targets nur fuer Linux.
#  Aufruf: bash build-linux.sh
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
TAURI_SRC="$SCRIPT_DIR/src-tauri"
TRIPLE="${CERNIS_BUILD_TRIPLE:-x86_64-unknown-linux-gnu}"

echo "============================================"
echo " CERNIS PRO Linux x86_64 Build"
echo " Ziel-Triple: $TRIPLE"
echo "============================================"

echo ""
echo "[0/8] System-Abhaengigkeiten pruefen..."
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
echo "[1/8] Frontend bauen..."
cd "$FRONTEND_DIR"
npm install --silent
npm run build
echo "      OK"

echo ""
echo "[2/8] Backend-Binary (cernis-backend)..."
cd "$BACKEND_DIR"
rm -rf dist/ build/
pyinstaller cernis_linux.spec --noconfirm
[ -f "$BACKEND_DIR/dist/cernis-backend" ] || { echo "FEHLER: cernis-backend fehlt"; exit 1; }
echo "      OK"

echo ""
echo "[3/8] Sniff-Helfer-Binary (cernis-sniffd)..."
cd "$BACKEND_DIR"
SNIFFD_BIN="$BACKEND_DIR/dist/cernis-sniffd"
pyinstaller cernis_sniffd_linux.spec --noconfirm
[ -f "$SNIFFD_BIN" ] || { echo "FEHLER: cernis-sniffd fehlt"; exit 1; }
echo "      OK"

echo ""
echo "[4/8] Sniff-Helfer verifizieren (keine Backend-only-Deps)..."
LEAK=0
for forbidden in fastapi uvicorn starlette reportlab; do
    if strings "$SNIFFD_BIN" | grep -qi "$forbidden"; then
        echo "      WARNUNG: '$forbidden' im sniffd-Binary"; LEAK=1
    fi
done
[ "$LEAK" -eq 0 ] && echo "      OK - schlank"

echo ""
echo "[5/8] Lizenzaufstellung erzeugen (inkl. nativer Bibliotheken)..."
# Der Zeitpunkt ist bindend: die mitgelieferten nativen Bibliotheken stammen aus der
# Abhaengigkeitsanalyse von PyInstaller und stehen erst JETZT fest - nach den
# Schritten 2/3 und vor dem Tauri-Build. Sie koennen nicht mehr in die Binaries
# hinein, deshalb geht die Aufstellung ueber bundle.resources ins Paket.
LIZENZ_JSON="$TAURI_SRC/lizenzaufstellung.json"
python3 "$SCRIPT_DIR/scripts/gen_license_manifest.py" "$LIZENZ_JSON" \
    --wurzel "$SCRIPT_DIR" \
    --binaerverzeichnis "$BACKEND_DIR/dist"
# Kein stiller Fallback: eine fehlende oder leere Aufstellung bricht den Bau ab.
[ -s "$LIZENZ_JSON" ] || { echo "FEHLER: $LIZENZ_JSON fehlt oder ist leer"; exit 1; }
# Die Wurzel-LICENSE kommt ueber dieselbe Ressourcenliste ins Paket. Kopie, das
# Original bleibt unberuehrt.
cp "$SCRIPT_DIR/LICENSE" "$TAURI_SRC/LICENSE"
[ -s "$TAURI_SRC/LICENSE" ] || { echo "FEHLER: $TAURI_SRC/LICENSE fehlt oder ist leer"; exit 1; }

# Aus derselben Aufstellung die beiden Debian-ueblichen Beilagen erzeugen. Sie
# gehen NICHT ueber bundle.resources (das landet unter /usr/lib/CernisPro/),
# sondern ueber bundle.linux.deb.files an die von Debian erwarteten Orte unter
# /usr/share/doc/cernis-pro/. Quelle ist allein die eben geschriebene
# Aufstellung; es wird nichts neu erhoben.
DEB_COPYRIGHT="$TAURI_SRC/debian/copyright"
DEB_LIZENZTEXTE="$TAURI_SRC/debian/3rd-party-licenses.txt.gz"
python3 "$SCRIPT_DIR/scripts/gen_debian_copyright.py" "$LIZENZ_JSON" \
    --copyright "$DEB_COPYRIGHT" \
    --lizenztexte "$DEB_LIZENZTEXTE"
# Kein stiller Fallback: fehlt eine der beiden Dateien, bricht der Bau ab.
[ -s "$DEB_COPYRIGHT" ] || { echo "FEHLER: $DEB_COPYRIGHT fehlt oder ist leer"; exit 1; }
[ -s "$DEB_LIZENZTEXTE" ] || { echo "FEHLER: $DEB_LIZENZTEXTE fehlt oder ist leer"; exit 1; }
echo "      OK"

echo ""
echo "[6/8] Binaries fuer Tauri bereitstellen (Triple $TRIPLE)..."
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
echo "[7/8] Tauri-Build (deb + rpm)..."
cd "$SCRIPT_DIR"
npm install --silent
npx tauri build --target "$TRIPLE"

echo ""
echo "[8/8] Pakete einsammeln..."
VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="$HOME/Desktop"; mkdir -p "$DEST"
BUNDLE_DIR="$TAURI_SRC/target/$TRIPLE/release/bundle"
DEB=$(find "$BUNDLE_DIR/deb" -name "*.deb" -print -quit 2>/dev/null || true)
[ -n "$DEB" ] && cp "$DEB" "$DEST/cernis-pro_${VERSION}_amd64.deb" && echo "      -> $DEST/cernis-pro_${VERSION}_amd64.deb"

echo ""
echo "============================================"
echo " BUILD ABGESCHLOSSEN (Version $VERSION)"
echo "============================================"
echo "Hinweis: deb-postinst.sh setzt nach Installation automatisch"
echo "  setcap cap_net_raw+eip /usr/bin/cernis-sniffd"
