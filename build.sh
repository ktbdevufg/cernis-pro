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
echo "[0/7] System-Abhaengigkeiten pruefen..."
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

# Signieridentitaet ERZWINGEN - vor dem ersten Build-Schritt, nicht am Ende.
# Ohne APPLE_SIGNING_IDENTITY faellt Tauri LAUTLOS auf eine Ad-hoc-Signatur zurueck.
# Das ist genau der stille Rueckfall auf ein schwaecheres Ergebnis, den dieses Projekt
# ausschliesst: der Build sieht erfolgreich aus, das Ergebnis ist aber nicht
# ausliefertauglich (kein TeamIdentifier, Gatekeeper lehnt ab).
if [ -z "${APPLE_SIGNING_IDENTITY:-}" ]; then
    echo "      FEHLER: APPLE_SIGNING_IDENTITY ist nicht gesetzt."
    echo "      Folge: Tauri wuerde still ad-hoc signieren - das Ergebnis waere NICHT"
    echo "      ausliefertauglich (keine Developer-ID, kein TeamIdentifier)."
    echo "      Weg:   Identitaet in der Shell-Konfiguration exportieren, hier ~/.zshrc:"
    echo "             export APPLE_SIGNING_IDENTITY=\"Developer ID Application: NAME (TEAMID)\""
    echo "      Vorhandene Identitaeten:  security find-identity -v -p codesigning"
    exit 1
fi

# Gesetzt ist nicht genug: die Identitaet muss im Schluesselbund auch vorhanden sein.
# Eine gesetzte, aber unbrauchbare Variable ist schlimmer als eine fehlende, weil sie
# Sicherheit vortaeuscht und der Fehlschlag erst beim Signieren auffiele.
# grep darf hier nichts finden, ohne das Skript zu beenden (set -e) -> "|| true".
IDENTITY_LISTE=$(security find-identity -v -p codesigning 2>/dev/null || true)
if ! printf '%s' "$IDENTITY_LISTE" | grep -qF "$APPLE_SIGNING_IDENTITY"; then
    echo "      FEHLER: APPLE_SIGNING_IDENTITY ist GESETZT, aber im Schluesselbund nicht"
    echo "      auffindbar (anders als der Fall 'gar nicht gesetzt'):"
    echo "        gesucht: $APPLE_SIGNING_IDENTITY"
    echo "      Der Wert muss exakt einer Codesigning-Identitaet entsprechen. Vorhanden:"
    echo "      security find-identity -v -p codesigning"
    exit 1
fi
echo "      Signieridentitaet: $APPLE_SIGNING_IDENTITY"

echo ""
echo "[0b/7] Build-Version erzeugen (_build_version.py)..."
SHORT_SHA=$(git rev-parse --short=7 HEAD)
# Produktversion aus pyproject.toml ableiten (Quelle der Wahrheit) -- nicht fest
# eintippen, damit der naechste Versionsbump hier automatisch ankommt.
PRODUCT_VERSION=$(grep -m1 -E '^version = ' "$SCRIPT_DIR/pyproject.toml" | sed -E 's/^version = "(.*)"/\1/')
[ -n "$PRODUCT_VERSION" ] || { echo "FEHLER: Produktversion aus pyproject.toml nicht lesbar"; exit 1; }
BUILD_VERSION="${PRODUCT_VERSION}+macos.${SHORT_SHA}"
cat > "$BACKEND_DIR/infrastructure/_build_version.py" << EOF
"""Im CI erzeugte Build-Version. Nicht committet (siehe .gitignore)."""
BUILD_VERSION = "${BUILD_VERSION}"
EOF
echo "      Build-Version: ${BUILD_VERSION}"

echo ""
echo "[1/7] Frontend bauen..."
cd "$FRONTEND_DIR"
npm install --silent
npm run build
echo "      OK"

echo ""
echo "[2/7] Backend-Binary (cernis-backend)..."
cd "$BACKEND_DIR"
rm -rf dist/ build/
pyinstaller cernis_macos.spec --noconfirm
[ -f "$BACKEND_DIR/dist/cernis-backend" ] || { echo "FEHLER: cernis-backend fehlt"; exit 1; }
echo "      OK"

echo ""
echo "[3/7] Sniff-Helfer-Binary (cernis-sniffd)..."
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

# ── Schritt 3c: Lizenzaufstellung erzeugen ──────────────────
# Spiegelbild von build-linux.sh Schritt [5/8] und build.ps1 Schritt [3d/6]. Der
# Zeitpunkt ist bindend und derselbe wie dort: NACH den PyInstaller-Laeufen (2/3)
# und VOR dem Tauri-Build (5). Die mitgelieferten nativen Bibliotheken stammen
# aus PyInstallers Abhaengigkeitsanalyse und stehen erst jetzt fest; in die
# Binaries koennen sie nicht mehr hinein, deshalb geht die Aufstellung ueber
# bundle.resources ins Paket. src-tauri/tauri.conf.json fuehrt
# lizenzaufstellung.json und LICENSE dort bereits -- keine Aenderung noetig.
#
# Der Schritt traegt 3c und nicht eine eigene Hauptnummer: dieses Skript
# nummeriert nachtraeglich eingefuegte Teilschritte seit jeher mit Buchstaben
# (0b, 3b). So bleibt die Gesamtzahl 7 richtig und keine der zehn bestehenden
# Zaehlerzeilen muss angefasst werden -- eine Durchnummerierung auf /8 haette
# alle zehn geaendert, ohne dass eine davon inhaltlich falsch gewesen waere.
echo ""
echo "[3c/7] Lizenzaufstellung erzeugen (inkl. nativer Bibliotheken)..."
LIZENZ_JSON="$TAURI_SRC/lizenzaufstellung.json"
# --zielplattform: die Plattform, FUER die gebaut wird. Der Sammler leitet daraus
# das Rust-Ziel und die Endungen der nativen Bibliotheken (.dylib) ab, statt sie
# aus der laufenden Maschine zu raten. Aus $TRIPLE abgeleitet, damit ein
# x64-Bau nicht stillschweigend die ARM-Aufstellung erzeugt. Ein unbekanntes
# Triple ist ein Abbruch, kein Rueckfall auf einen Vorgabewert.
case "$TRIPLE" in
    x86_64-*)  ZIELPLATTFORM="macos-x86_64" ;;
    aarch64-*) ZIELPLATTFORM="macos-aarch64" ;;
    *)
        echo "FEHLER: Unbekanntes Triple '$TRIPLE' -- kann Zielplattform nicht ableiten."
        exit 1
        ;;
esac
python3 "$SCRIPT_DIR/scripts/gen_license_manifest.py" "$LIZENZ_JSON" \
    --wurzel "$SCRIPT_DIR" \
    --binaerverzeichnis "$BACKEND_DIR/dist" \
    --zielplattform "$ZIELPLATTFORM"
# Kein stiller Fallback: eine fehlende oder leere Aufstellung bricht den Bau ab
# (build-linux.sh Zeile 87).
[ -s "$LIZENZ_JSON" ] || { echo "FEHLER: $LIZENZ_JSON fehlt oder ist leer"; exit 1; }
# Die Wurzel-LICENSE kommt ueber dieselbe Ressourcenliste ins Paket. Kopie, das
# Original bleibt unberuehrt (build-linux.sh Zeile 89).
cp "$SCRIPT_DIR/LICENSE" "$TAURI_SRC/LICENSE"
[ -s "$TAURI_SRC/LICENSE" ] || { echo "FEHLER: $TAURI_SRC/LICENSE fehlt oder ist leer"; exit 1; }
# Die Debian- und die Fedora-Beilage entstehen hier bewusst NICHT: macOS baut ein
# .dmg; copyright, 3rd-party-licenses.txt.gz, LICENSE.dependencies und LICENSES
# gehoeren dort nicht hin. Eine plattformuebliche macOS-Ablage ist ein eigenes
# Arbeitspaket.
echo "      OK"

echo ""
echo "[4/7] Binaries fuer Tauri bereitstellen (Triple $TRIPLE)..."
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
echo "[5/7] Tauri-Build (.dmg)..."
cd "$SCRIPT_DIR"
npm install --silent
npx tauri build --target "$TRIPLE"

echo ""
echo "[6/7] Signatur der gebauten .app verifizieren..."
# Bewusst VOR dem Einsammeln: ein Build mit unbrauchbarer Signatur darf nicht als
# Erfolg enden und nicht auf dem Schreibtisch landen.
BUNDLE_DIR="$TAURI_SRC/target/$TRIPLE/release/bundle"
# Den .app-Pfad ERMITTELN, nicht raten (der Bundle-Name haengt an productName).
APP_PFAD=$(find "$BUNDLE_DIR/macos" -maxdepth 1 -name "*.app" -print -quit 2>/dev/null || true)
if [ -z "$APP_PFAD" ]; then
    echo "      FEHLER: keine .app unter $BUNDLE_DIR/macos gefunden."
    exit 1
fi
echo "      Geprueft wird: $APP_PFAD"

# (a) Gueltigkeit streng pruefen. codesign schreibt AUF STDERR -> 2>&1, sonst bliebe
# die Ausgabe leer und die inhaltliche Pruefung ginge faelschlich durch.
# "|| true" haelt set -e zurueck, damit die Meldung unten ausgegeben werden kann;
# der Rueckgabewert wird getrennt in CODESIGN_RC festgehalten.
CODESIGN_AUSGABE=$(codesign --verify --deep --strict --verbose=2 "$APP_PFAD" 2>&1) && CODESIGN_RC=0 || CODESIGN_RC=$?
if [ "$CODESIGN_RC" -ne 0 ]; then
    echo "      FEHLER: Signaturpruefung fehlgeschlagen (codesign, Exit $CODESIGN_RC):"
    printf '        %s\n' "$CODESIGN_AUSGABE"
    exit 1
fi

# (b) Inhaltlich pruefen: KEINE Ad-hoc-Signatur, sondern echte Developer-ID mit
# gesetztem TeamIdentifier. Der Rueckgabewert allein genuegt nicht - eine ad-hoc
# signierte .app besteht (a) anstandslos, meldet hier aber "Signature=adhoc"
# bzw. "TeamIdentifier=not set".
SIGN_INFO=$(codesign --display --verbose=4 "$APP_PFAD" 2>&1 || true)
if printf '%s' "$SIGN_INFO" | grep -q "Signature=adhoc"; then
    echo "      FEHLER: die .app ist AD-HOC signiert - nicht ausliefertauglich."
    echo "      Erwartet war eine Developer-ID-Signatur mit APPLE_SIGNING_IDENTITY."
    exit 1
fi
TEAM_ID=$(printf '%s' "$SIGN_INFO" | grep "^TeamIdentifier=" | head -1 | cut -d= -f2)
if [ -z "$TEAM_ID" ] || [ "$TEAM_ID" = "not set" ]; then
    echo "      FEHLER: kein TeamIdentifier in der Signatur (Wert: '${TEAM_ID:-leer}')."
    echo "      Ohne TeamIdentifier ist die .app nicht ausliefertauglich."
    exit 1
fi
AUTHORITY=$(printf '%s' "$SIGN_INFO" | grep "^Authority=" | head -1 | cut -d= -f2-)
echo "      OK - Identitaet: ${AUTHORITY:-unbekannt} (TeamIdentifier: $TEAM_ID)"

echo ""
echo "[7/7] Pakete einsammeln..."
VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="$HOME/Desktop"; mkdir -p "$DEST"
DMG=$(find "$BUNDLE_DIR/dmg" -name "*.dmg" -print -quit 2>/dev/null || true)
[ -n "$DMG" ] && cp "$DMG" "$DEST/cernis-pro_${VERSION}_aarch64.dmg" && echo "      -> $DEST/cernis-pro_${VERSION}_aarch64.dmg"

echo ""
echo "============================================"
echo " BUILD ABGESCHLOSSEN (Version $VERSION)"
echo "============================================"
echo "Hinweis: Die Anwendung ist mit der Developer-ID signiert und verifiziert."
echo "  Die Sniff-Rechte werden beim ersten Bedarf aus der Anwendung heraus eingerichtet"
echo "  (Gruppe cernis-capture, gesetzt per LaunchDaemon; jederzeit widerrufbar)."
echo "  Die Notarisierung erfolgt separat als letzter Schritt vor einer Auslieferung."
