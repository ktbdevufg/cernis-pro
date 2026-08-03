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

# Aus DERSELBEN Aufstellung die beiden RPM-ueblichen Beilagen erzeugen. Sie gehen
# ueber bundle.linux.rpm.files an den von Fedora erwarteten Ort
# /usr/share/licenses/cernis-pro/ (Makro _defaultlicensedir). Getrenntes
# Zielverzeichnis src-tauri/rpm/, damit sich deb- und rpm-Beilagen nicht
# vermischen. Auch hier wird nichts neu erhoben.
RPM_DEPENDENCIES="$TAURI_SRC/rpm/LICENSE.dependencies"
RPM_LIZENZTEXTE="$TAURI_SRC/rpm/LICENSES"
python3 "$SCRIPT_DIR/scripts/gen_rpm_licenses.py" "$LIZENZ_JSON" \
    --dependencies "$RPM_DEPENDENCIES" \
    --lizenztexte "$RPM_LIZENZTEXTE"
# Kein stiller Fallback: fehlt eine der beiden Dateien, bricht der Bau ab.
[ -s "$RPM_DEPENDENCIES" ] || { echo "FEHLER: $RPM_DEPENDENCIES fehlt oder ist leer"; exit 1; }
[ -s "$RPM_LIZENZTEXTE" ] || { echo "FEHLER: $RPM_LIZENZTEXTE fehlt oder ist leer"; exit 1; }
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

# ── Schritt 7b: Waechter Vorhandensein der Beilage ──────────
# Warum ueberhaupt: ein Bau kann mit RC=0 durchlaufen, OHNE dass die Beilage im
# Paket ankommt -- auf macOS ist genau das passiert (stille Array-Ersetzung der
# bundle.resources nach RFC 7396), und gefunden wurde es von Hand, nicht vom
# Bau. Ein gruener Bau belegt eben nicht seinen Inhalt. Hier kommt hinzu, dass
# die vier Beilagen ueber ZWEI verschiedene Wege ins Paket gehen: die beiden
# unter /usr/lib/CernisPro/ ueber bundle.resources, die uebrigen ueber
# bundle.linux.deb.files bzw. bundle.linux.rpm.files. Jeder Weg kann fuer sich
# ausfallen, ohne dass der Bau es meldet.
#
# Die Stelle ist bindend: NACH Schritt [7/8] und VOR Schritt [8/8]. Die Pakete
# liegen hier fertig vor -- geprueft wird also am ECHTEN Erzeugnis, IM Paket,
# nicht am Quellverzeichnis und nicht an dem, was der Bau abgelegt zu haben
# glaubt. Und weil das Einsammeln erst danach kommt, kann ein Paket mit
# fehlender Beilage nicht auf dem Schreibtisch landen.
#
# Der Waechter prueft NUR und legt NICHTS nach: ein nachtraegliches Einfuegen
# waere ein stiller Rueckfall auf ein Paket, das der Bau so nie erzeugt hat.
#
# Der Schritt traegt 7b und nicht eine eigene Hauptnummer, damit die Gesamtzahl
# 8 richtig bleibt und keine der bestehenden Zaehlerzeilen angefasst werden muss.
echo ""
echo "[7b/8] Beilage in den gebauten Paketen pruefen (Waechter)..."
BUNDLE_DIR="$TAURI_SRC/target/$TRIPLE/release/bundle"
BEILAGE_FEHLT=0

# Ein Eintrag je erwarteter Datei, EINZELN und namentlich -- eine Sammelmeldung
# "irgendetwas fehlt" liesse offen, wonach zu suchen waere. Das Feld hinter dem
# Doppelpunkt nennt die naechstliegende Ursache.
DEB_ERWARTET=(
    "/usr/lib/CernisPro/lizenzaufstellung.json:bundle.resources in src-tauri/tauri.conf.json"
    "/usr/lib/CernisPro/LICENSE:bundle.resources in src-tauri/tauri.conf.json"
    "/usr/share/doc/cernis-pro/copyright:bundle.linux.deb.files in src-tauri/tauri.conf.json (Quelle: debian/copyright aus Schritt [5/8])"
    "/usr/share/doc/cernis-pro/3rd-party-licenses.txt.gz:bundle.linux.deb.files in src-tauri/tauri.conf.json (Quelle: debian/3rd-party-licenses.txt.gz aus Schritt [5/8])"
)
RPM_ERWARTET=(
    "/usr/lib/CernisPro/lizenzaufstellung.json:bundle.resources in src-tauri/tauri.conf.json"
    "/usr/lib/CernisPro/LICENSE:bundle.resources in src-tauri/tauri.conf.json"
    "/usr/share/licenses/cernis-pro/LICENSE.dependencies:bundle.linux.rpm.files in src-tauri/tauri.conf.json (Quelle: rpm/LICENSE.dependencies aus Schritt [5/8])"
    "/usr/share/licenses/cernis-pro/LICENSES:bundle.linux.rpm.files in src-tauri/tauri.conf.json (Quelle: rpm/LICENSES aus Schritt [5/8])"
)

# Im Paket nachsehen, mit den Werkzeugen der Plattform: dpkg-deb bzw.
# rpm2cpio+cpio listen den Inhalt samt Groesse, ohne zu installieren. Fehlt das
# Werkzeug, ist das ein Abbruch und kein Ueberspringen -- eine uebersprungene
# Pruefung ist genau der stille Rueckfall, den dieses Projekt ausschliesst.
DEB_PAKET=$(find "$BUNDLE_DIR/deb" -name "*.deb" -print -quit 2>/dev/null || true)
if [ -z "$DEB_PAKET" ]; then
    echo "      FEHLER: kein .deb unter $BUNDLE_DIR/deb gefunden."
    exit 1
fi
command -v dpkg-deb >/dev/null 2>&1 || { echo "      FEHLER: dpkg-deb fehlt - die Beilage im .deb ist nicht pruefbar. Bitte: sudo apt install dpkg"; exit 1; }
echo "      Geprueft wird: $DEB_PAKET"
# Format je Zeile: "Rechte Eigner Groesse Datum Zeit ./pfad" -> Groesse in $3,
# Pfad in $6 (fuehrendes "." abschneiden). Vorhandensein UND Groesse in einem
# Zug: eine leere Beilage ist dasselbe wie keine.
DEB_INHALT=$(dpkg-deb -c "$DEB_PAKET" | awk '{ pfad=$6; sub(/^\./, "", pfad); print pfad "\t" $3 }')
for eintrag in "${DEB_ERWARTET[@]}"; do
    pfad="${eintrag%%:*}"; ursache="${eintrag#*:}"
    groesse=$(printf '%s\n' "$DEB_INHALT" | awk -F'\t' -v p="$pfad" '$1==p { print $2; exit }')
    if [ -z "$groesse" ]; then
        echo "      FEHLER: '$pfad' fehlt im gebauten .deb."
        echo "        erwarteter Ort:       $pfad (im Paket)"
        echo "        geprueftes Erzeugnis: $DEB_PAKET"
        echo "        naechstliegende Ursache: fehlender oder falscher Eintrag unter $ursache"
        BEILAGE_FEHLT=1
    elif [ "$groesse" -eq 0 ]; then
        echo "      FEHLER: '$pfad' ist LEER im gebauten .deb (0 Bytes)."
        echo "        erwarteter Ort:       $pfad (im Paket)"
        echo "        geprueftes Erzeugnis: $DEB_PAKET"
        echo "        naechstliegende Ursache: die Quelldatei war beim Tauri-Bau bereits leer - siehe Schritt [5/8]"
        BEILAGE_FEHLT=1
    else
        echo "      OK - deb: $pfad ($groesse Bytes)"
    fi
done

RPM_PAKET=$(find "$BUNDLE_DIR/rpm" -name "*.rpm" -print -quit 2>/dev/null || true)
if [ -z "$RPM_PAKET" ]; then
    echo "      FEHLER: kein .rpm unter $BUNDLE_DIR/rpm gefunden."
    exit 1
fi
command -v rpm >/dev/null 2>&1 || { echo "      FEHLER: rpm fehlt - die Beilage im .rpm ist nicht pruefbar. Bitte: sudo apt install rpm"; exit 1; }
echo "      Geprueft wird: $RPM_PAKET"
# -qp fragt die PAKETDATEI ab (nicht die installierte Datenbank), --dump liefert
# je Datei "pfad groesse mtime ..." -- Vorhandensein und Groesse in einem Zug.
RPM_INHALT=$(rpm -qp --dump "$RPM_PAKET" 2>/dev/null | awk '{ print $1 "\t" $2 }')
for eintrag in "${RPM_ERWARTET[@]}"; do
    pfad="${eintrag%%:*}"; ursache="${eintrag#*:}"
    groesse=$(printf '%s\n' "$RPM_INHALT" | awk -F'\t' -v p="$pfad" '$1==p { print $2; exit }')
    if [ -z "$groesse" ]; then
        echo "      FEHLER: '$pfad' fehlt im gebauten .rpm."
        echo "        erwarteter Ort:       $pfad (im Paket)"
        echo "        geprueftes Erzeugnis: $RPM_PAKET"
        echo "        naechstliegende Ursache: fehlender oder falscher Eintrag unter $ursache"
        BEILAGE_FEHLT=1
    elif [ "$groesse" -eq 0 ]; then
        echo "      FEHLER: '$pfad' ist LEER im gebauten .rpm (0 Bytes)."
        echo "        erwarteter Ort:       $pfad (im Paket)"
        echo "        geprueftes Erzeugnis: $RPM_PAKET"
        echo "        naechstliegende Ursache: die Quelldatei war beim Tauri-Bau bereits leer - siehe Schritt [5/8]"
        BEILAGE_FEHLT=1
    else
        echo "      OK - rpm: $pfad ($groesse Bytes)"
    fi
done

# Fehlt etwas, bricht der Bau ab: kein Warnhinweis, kein Weiterlaufen, kein
# Einsammeln.
if [ "$BEILAGE_FEHLT" -ne 0 ]; then
    echo "      Der Bau wird abgebrochen. Es wird NICHTS nachgelegt und NICHTS"
    echo "      repariert -- das waere ein stiller Rueckfall auf ein Paket, das"
    echo "      der Bau so nie erzeugt hat."
    echo "      Weg: Ursache oben beheben und neu bauen."
    exit 1
fi

echo ""
echo "[8/8] Pakete einsammeln..."
VERSION=$(python3 -c "import json; print(json.load(open('$TAURI_SRC/tauri.conf.json'))['version'])")
DEST="$HOME/Desktop"; mkdir -p "$DEST"
DEB=$(find "$BUNDLE_DIR/deb" -name "*.deb" -print -quit 2>/dev/null || true)
[ -n "$DEB" ] && cp "$DEB" "$DEST/cernis-pro_${VERSION}_amd64.deb" && echo "      -> $DEST/cernis-pro_${VERSION}_amd64.deb"

echo ""
echo "============================================"
echo " BUILD ABGESCHLOSSEN (Version $VERSION)"
echo "============================================"
echo "Hinweis: deb-postinst.sh setzt nach Installation automatisch"
echo "  setcap cap_net_raw+eip /usr/bin/cernis-sniffd"
