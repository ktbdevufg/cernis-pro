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

# ── Schritt 4b: Wurzel-Abhaengigkeiten installieren ─────────
# Die Reihenfolge ist bindend und darf NICHT zurueckgedreht werden: der
# Sammler in [5/8] liest die AUFGELOESTEN Wurzel-Abhaengigkeiten ueber
# 'npm ls --omit=dev' im Wurzelverzeichnis. Ohne node_modules an der Wurzel
# loest sich keine einzige der erklaerten produktiven Abhaengigkeiten auf, und
# der npm-Waechter des Sammlers bricht ab.
#
# Anlass ist Befund 25, gemessen am Linux-Bau 30842765403 auf GitHub Actions:
# das Wurzel-Install stand frueher erst in [7/8], unmittelbar vor dem
# Tauri-Bau -- also NACH dem Sammler. Auf Maschinen mit einem node_modules aus
# frueheren Laeufen fiel das nicht auf, im frisch gebauten Container brach der
# Bau in [5/8] sofort ab.
#
# Das Install steht nur noch HIER, nicht mehr zusaetzlich in [7/8]: zweimal
# ausgefuehrt kostet es Zeit, ohne etwas zu aendern. Der Tauri-Bau findet die
# CLI unveraendert vor, denn zwischen hier und [7/8] wird an node_modules
# nichts angefasst.
#
# Der Schritt traegt 4b und nicht eine eigene Hauptnummer, damit die Gesamtzahl
# 8 richtig bleibt und keine der bestehenden Zaehlerzeilen angefasst werden muss.
echo ""
echo "[4b/8] Wurzel-Abhaengigkeiten installieren (fuer Sammler und Tauri-CLI)..."
cd "$SCRIPT_DIR"
npm install --silent
echo "      OK"

echo ""
echo "[5/8] Lizenzaufstellung erzeugen (inkl. nativer Bibliotheken)..."
# Der Zeitpunkt ist bindend: die mitgelieferten nativen Bibliotheken stammen aus der
# Abhaengigkeitsanalyse von PyInstaller und stehen erst JETZT fest - nach den
# Schritten 2/3 und vor dem Tauri-Build. Sie koennen nicht mehr in die Binaries
# hinein, deshalb geht die Aufstellung ueber bundle.resources ins Paket.
LIZENZ_JSON="$TAURI_SRC/lizenzaufstellung.json"
# --zielplattform: die Plattform, FUER die gebaut wird. Der Sammler leitet daraus
# das Rust-Ziel und die Endungen der nativen Bibliotheken (.so) ab, statt sie aus
# der laufenden Maschine zu raten. Aus $TRIPLE abgeleitet, damit ein ARM64-Bau
# nicht stillschweigend die x64-Aufstellung erzeugt. Ein unbekanntes Triple ist
# ein Abbruch, kein Rueckfall auf einen Vorgabewert.
case "$TRIPLE" in
    x86_64-*)  ZIELPLATTFORM="linux-x86_64" ;;
    aarch64-*) ZIELPLATTFORM="linux-aarch64" ;;
    *)
        echo "FEHLER: Unbekanntes Triple '$TRIPLE' -- kann Zielplattform nicht ableiten."
        exit 1
        ;;
esac
python3 "$SCRIPT_DIR/scripts/gen_license_manifest.py" "$LIZENZ_JSON" \
    --wurzel "$SCRIPT_DIR" \
    --binaerverzeichnis "$BACKEND_DIR/dist" \
    --zielplattform "$ZIELPLATTFORM"
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

# ── Schritt 6b: Buendelverzeichnis leeren, BEVOR gebuendelt wird ─
# Warum: unter BUNDLE_DIR/deb und BUNDLE_DIR/rpm sammeln sich Altbestaende
# frueherer Laeufe an -- gemessen lagen dort Paketdateien UND aufgebaute
# Staging-Verzeichnisse der Fassung 2.0.6 vom 2026-08-02 neben denen von 2.1.0.
# Weder Cargo noch der Buendler raeumen dort auf. Ein leeres Verzeichnis vor dem
# Bau heisst: was danach drinliegt, hat GENAU dieser Lauf erzeugt.
#
# Kein stilles Wegraeumen: jeder entfernte Eintrag wird namentlich genannt, und
# wenn nichts zu entfernen war, wird auch DAS gesagt. Eine Loeschroutine, die
# schweigt, ist nicht nachvollziehbar.
#
# Riegel: geloescht wird ausschliesslich INNERHALB von BUNDLE_DIR/deb und
# BUNDLE_DIR/rpm. Ist BUNDLE_DIR leer oder nicht gesetzt, bricht der Schritt ab,
# statt mit einem leeren Praefix auf die Wurzel loszugehen. Das ist eine
# Loeschroutine in einem Bauskript -- sie braucht diesen Riegel.
#
# Die versionsgenaue Wahl in paket_dieses_baus_waehlen [7b/8] BLEIBT bestehen und
# wird durch dieses Aufraeumen NICHT ueberfluessig: sie ist die Stelle, die redet,
# falls die Annahme ueber das Verzeichnis doch einmal nicht stimmt -- etwa wenn
# der Buendler kuenftig woanders ablegt, dieser Schritt also am falschen Ort
# raeumt, oder wenn ein Lauf mehrere Fassungen erzeugt. Ein Waechter, der sich
# auf ein vorher geleertes Verzeichnis VERLAESST, waere genau wieder ein
# "der erste Treffer wird schon stimmen".
#
# Der Schritt traegt 6b und nicht eine eigene Hauptnummer, damit die Gesamtzahl
# 8 richtig bleibt und keine der bestehenden Zaehlerzeilen angefasst werden muss.
BUNDLE_DIR="$TAURI_SRC/target/$TRIPLE/release/bundle"
echo ""
echo "[6b/8] Buendelverzeichnis leeren (Altbestaende frueherer Laeufe)..."
if [ -z "${BUNDLE_DIR:-}" ]; then
    echo "      FEHLER: BUNDLE_DIR ist leer oder nicht gesetzt -- es wird NICHTS geloescht."
    exit 1
fi
for BUENDEL_UNTER in deb rpm; do
    BUENDEL_ZIEL="$BUNDLE_DIR/$BUENDEL_UNTER"
    if [ ! -d "$BUENDEL_ZIEL" ]; then
        echo "      $BUENDEL_UNTER: Verzeichnis existiert noch nicht ($BUENDEL_ZIEL) - nichts zu entfernen."
        continue
    fi
    ENTFERNT=0
    # -mindepth 1 -maxdepth 1: nur die unmittelbaren Eintraege, und das
    # Verzeichnis selbst bleibt stehen. Kein Glob, damit auch Eintraege mit
    # Punkt am Anfang erfasst werden.
    while IFS= read -r EINTRAG; do
        [ -n "$EINTRAG" ] || continue
        echo "      $BUENDEL_UNTER: entferne $EINTRAG"
        rm -rf "$EINTRAG"
        ENTFERNT=$((ENTFERNT + 1))
    done < <(find "$BUENDEL_ZIEL" -mindepth 1 -maxdepth 1 | sort)
    if [ "$ENTFERNT" -eq 0 ]; then
        echo "      $BUENDEL_UNTER: nichts zu entfernen - $BUENDEL_ZIEL war bereits leer."
    else
        echo "      $BUENDEL_UNTER: $ENTFERNT Eintraege entfernt."
    fi
done
echo "      OK"

echo ""
echo "[7/8] Tauri-Build (deb + rpm)..."
# Das Wurzel-npm-Install steht seit Befund 25 in [4b/8] und NICHT mehr hier:
# der Sammler in [5/8] braucht es bereits. Ein zweiter Lauf an dieser Stelle
# waere wirkungslos, denn zwischendurch wird an node_modules nichts angefasst.
cd "$SCRIPT_DIR"
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
# BUNDLE_DIR ist bereits in [6b/8] gesetzt -- eine zweite Zuweisung waere eine
# zweite Quelle fuer denselben Pfad und koennte auseinanderlaufen.
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

# Geprueft wird am ENTPACKTEN Paket, nicht an einer Textausgabe. Grund: die
# Auswertung von "dpkg-deb -c" ueber Spaltennummern hat in Lauf 30843987085
# falschen Alarm fuer alle vier deb-Beilagen erzeugt, obwohl in Sitzung 72 am
# gebauten deb belegt war, dass sie ankommen. Ein Dateibaum laesst sich mit
# test -s eindeutig befragen -- da gibt es keine Spalten, die verrutschen
# koennen. Vorbild ist der Schritt "Verifikation -- gebundelte libpcap ohne
# libibverbs" in .github/workflows/build-linux.yml, der genauso arbeitet:
# mktemp -d, dpkg-deb -x, dann am Baum pruefen.
#
# Zur Pfadabbildung: im Paket stehen die Pfade relativ (deb listet sie mit
# fuehrendem "./"). Beim Entpacken nach $WORK entsteht daraus ein Dateibaum, in
# dem der erwartete absolute Pfad /usr/lib/... unter $WORK/usr/lib/... liegt.
# Die Abbildung ist also schlicht "$WORK$pfad" -- der fuehrende Schraegstrich
# des erwarteten Pfades wird zum Trenner zwischen Wurzel und Baum. Genau
# deshalb muessen die Eintraege in den ERWARTET-Listen absolut bleiben.
#
# Fehlt das Entpackwerkzeug, ist das ein Abbruch und kein Ueberspringen -- eine
# uebersprungene Pruefung ist genau der stille Rueckfall, den dieses Projekt
# ausschliesst.

# Die temporaeren Verzeichnisse werden in jedem Fall wieder entfernt, auch bei
# Abbruch: sonst bleibt bei jedem Fehlschlag ein entpacktes Paket liegen.
WAECHTER_TMP=""
waechter_aufraeumen() { [ -n "$WAECHTER_TMP" ] && rm -rf $WAECHTER_TMP; }
trap waechter_aufraeumen EXIT

# Eine erwartete Datei am entpackten Baum pruefen: Vorhandensein UND nicht leer.
# test -s ist beides in einem Zug -- eine leere Beilage ist dasselbe wie keine.
# $1 Wurzel des entpackten Baums, $2 erwarteter absoluter Pfad, $3 Ursache,
# $4 Erzeugnis (Pfad der Paketdatei), $5 Kennung fuer die Meldung (deb/rpm).
beilage_pruefen() {
    local wurzel="$1" pfad="$2" ursache="$3" erzeugnis="$4" art="$5"
    local ziel="$wurzel$pfad"
    if [ ! -e "$ziel" ]; then
        echo "      FEHLER: '$pfad' fehlt im gebauten .$art."
        echo "        erwarteter Ort:       $pfad (im Paket)"
        echo "        geprueftes Erzeugnis: $erzeugnis"
        echo "        naechstliegende Ursache: fehlender oder falscher Eintrag unter $ursache"
        BEILAGE_FEHLT=1
    elif [ ! -s "$ziel" ]; then
        echo "      FEHLER: '$pfad' ist LEER im gebauten .$art (0 Bytes)."
        echo "        erwarteter Ort:       $pfad (im Paket)"
        echo "        geprueftes Erzeugnis: $erzeugnis"
        echo "        naechstliegende Ursache: die Quelldatei war beim Tauri-Bau bereits leer - siehe Schritt [5/8]"
        BEILAGE_FEHLT=1
    else
        echo "      OK - $art: $pfad ($(wc -c < "$ziel" | tr -d ' ') Bytes)"
    fi
}

# Zweiter, UNABHAENGIGER Waechter: findet die Anwendung die Aufstellung zur
# LAUFZEIT? Die Beilagenpruefung oben belegt nur die ABLAGE an einem erwarteten
# Ort -- und diese Erwartung ist im Repo nirgends gemessen, sondern notiert. Ein
# Paket kann die Datei also mustergueltig an dem Ort tragen, den die Liste nennt,
# und die Anwendung findet sie trotzdem nicht, weil sie an einer ANDEREN Stelle
# sucht. Deshalb nimmt dieser Waechter die Erwartungsliste ausdruecklich NICHT
# zum Massstab, sondern allein die Suchlogik der Anwendung:
# backend/infrastructure/license_manifest.py, Funktion _kandidaten. Sie leitet
# alle Kandidaten aus sys.executable ab -- also aus dem Ort des Backend-Binaers
# im Paket, nicht aus einem konfigurierten Pfad.
#
# $1 Wurzel des entpackten Baums, $2 Erzeugnis (Pfad der Paketdatei),
# $3 Kennung fuer die Meldung (deb/rpm).
laufzeitfund_pruefen() {
    local wurzel="$1" erzeugnis="$2" art="$3"
    local dateiname="lizenzaufstellung.json"

    # Erstens: das Backend-Binaer im Baum. Genau ein Treffer wird erwartet --
    # null bedeutet, dass das Paket das Backend gar nicht traegt, mehr als einer
    # macht die Ableitung von sys.executable mehrdeutig. Beides ist ein Abbruch
    # mit benannter Trefferzahl, kein Ueberspringen.
    local treffer anzahl
    treffer=$(find "$wurzel" -name "cernis-backend" -type f)
    anzahl=$(printf '%s' "$treffer" | grep -c . || true)
    if [ "$anzahl" -ne 1 ]; then
        echo "      FEHLER: im gebauten .$art wurden $anzahl Dateien namens 'cernis-backend' gefunden, erwartet ist genau eine."
        echo "        geprueftes Erzeugnis: $erzeugnis"
        if [ "$anzahl" -gt 1 ]; then
            while IFS= read -r fund; do
                echo "        Treffer: ${fund#"$wurzel"}"
            done <<< "$treffer"
        fi
        echo "        Ohne eindeutiges Backend-Binaer laesst sich sys.executable nicht abbilden"
        echo "        und damit die Laufzeitsuche nicht nachvollziehen."
        BEILAGE_FEHLT=1
        return
    fi

    # Zweitens: der Installationspfad des Verzeichnisses, in dem das Binaer
    # liegt -- also der Pfad relativ zur Baumwurzel mit fuehrendem
    # Schraegstrich. Genau dieses Verzeichnis ist zur Laufzeit
    # os.path.dirname(sys.executable).
    local exe_verzeichnis exe_install
    exe_verzeichnis=$(dirname "$treffer")
    exe_install="${exe_verzeichnis#"$wurzel"}"
    echo "      Laufzeit-$art: Backend-Binaer liegt in $exe_install"

    # Drittens: wo liegt die Aufstellung TATSAECHLICH? Das ist die erste Messung
    # dieses Ortes ueberhaupt -- sie gehoert deshalb auch im Erfolgsfall in die
    # Ausgabe, nicht nur in eine Fehlermeldung.
    local aufstellung_roh aufstellung_orte orte_text
    aufstellung_roh=$(find "$wurzel" -name "$dateiname" -type f | sort)
    aufstellung_orte=""
    if [ -n "$aufstellung_roh" ]; then
        while IFS= read -r fund; do
            aufstellung_orte+="${fund#"$wurzel"}"$'\n'
        done <<< "$aufstellung_roh"
        aufstellung_orte="${aufstellung_orte%$'\n'}"
    fi
    if [ -z "$aufstellung_orte" ]; then
        orte_text="(keine)"
        echo "      Laufzeit-$art: '$dateiname' liegt nirgends im Paket"
    else
        orte_text=$(printf '%s' "$aufstellung_orte" | tr '\n' ' ')
        while IFS= read -r ort; do
            echo "      Laufzeit-$art: '$dateiname' liegt unter $ort"
        done <<< "$aufstellung_orte"
    fi

    # Viertens: die Kandidaten bilden, exakt wie _kandidaten es tut.
    # Kandidat 1 ist die macOS-Form <verzeichnis>/../Resources/<datei>; nach
    # os.path.normpath faellt das ".." mit der letzten Komponente des
    # Verzeichnisses zusammen, uebrig bleibt <elternverzeichnis>/Resources/<datei>.
    # Kandidat 2 ist die Form <verzeichnis>/<datei> -- sie deckt Windows ab.
    # Kandidat 3 ist die Linux-Paketform <verzeichnis>/../lib/CernisPro/<datei>:
    # das Backend geht ueber externalBin nach /usr/bin, die Aufstellung ueber
    # bundle.resources nach /usr/lib/CernisPro (Befund 34b, an diesem Paket
    # gemessen). Auch hier faellt das ".." nach normpath mit der letzten
    # Komponente des Verzeichnisses zusammen. Der VIERTE Kandidat aus
    # _kandidaten bleibt hier bewusst AUSSEN VOR: er zeigt auf src-tauri/ unter
    # der Repo-Wurzel, die aus dem Ort der Python-Datei abgeleitet wird. Auf
    # einem Zielsystem existiert dieses Verzeichnis nicht -- ein Treffer dort
    # waere ein Artefakt der Baumaschine und wuerde genau den Fehlschlag
    # verdecken, den dieser Waechter sucht.
    local kandidat1 kandidat2 kandidat3
    kandidat1="$(dirname "$exe_install")/Resources/$dateiname"
    kandidat2="$exe_install/$dateiname"
    kandidat3="$(dirname "$exe_install")/lib/CernisPro/$dateiname"

    # Fuenftens: existiert einer der drei Kandidaten im Baum als nicht leere
    # Datei? Leer zaehlt wie fehlend -- eine leere Aufstellung ist zur Laufzeit
    # kein lesbares JSON-Objekt. Die Reihenfolge ist dieselbe wie in
    # _kandidaten; geprueft wird der ERSTE Treffer, denn genau den nimmt auch
    # die Anwendung.
    local gefunden=""
    if [ -s "$wurzel$kandidat1" ]; then
        gefunden="$kandidat1"
    elif [ -s "$wurzel$kandidat2" ]; then
        gefunden="$kandidat2"
    elif [ -s "$wurzel$kandidat3" ]; then
        gefunden="$kandidat3"
    fi

    if [ -n "$gefunden" ]; then
        echo "      OK - $art: Laufzeitfund unter $gefunden ($(wc -c < "$wurzel$gefunden" | tr -d ' ') Bytes)"
        return
    fi

    echo "      FEHLER: die Anwendung findet '$dateiname' im gebauten .$art an KEINEM ihrer Laufzeit-Kandidatenorte."
    echo "        geprueftes Erzeugnis:     $erzeugnis"
    echo "        Backend-Binaer liegt in:  $exe_install"
    echo "        Aufstellung liegt unter:  $orte_text"
    echo "        gepruefter Kandidat 1:    $kandidat1"
    echo "        gepruefter Kandidat 2:    $kandidat2"
    echo "        gepruefter Kandidat 3:    $kandidat3"
    echo "        naechstliegende Ursache: das Backend wird ueber externalBin ausgeliefert"
    echo "        und landet damit in einem ANDEREN Verzeichnis als die Eintraege aus"
    echo "        bundle.resources. Die aus sys.executable abgeleiteten Kandidaten zeigen"
    echo "        deshalb am Ablageort der Aufstellung vorbei."
    BEILAGE_FEHLT=1
}

# Die Produktversion DIESES Laufs -- aus der in Schritt [5/8] erzeugten Aufstellung,
# nicht aus tauri.conf.json: geprueft werden soll das Erzeugnis, das zu GENAU dieser
# Aufstellung gehoert. Fehlt das Feld, ist das ein Abbruch und kein Rueckfall.
PRODUKTVERSION=$(python3 -c "
import json, sys
daten = json.load(open(sys.argv[1]))
wert = daten.get('produktversion')
if not isinstance(wert, str) or not wert:
    sys.exit('FEHLER: die erzeugte Aufstellung fuehrt kein Feld produktversion.')
print(wert)
" "$LIZENZ_JSON") || exit 1
echo "      Produktversion dieses Laufs (aus $LIZENZ_JSON): $PRODUKTVERSION"

# Das zu pruefende Paket waehlen -- versionsgenau, nicht "der erste Treffer".
# Warum: im Bundle-Verzeichnis liegen Altbestaende frueherer Laeufe (gemessen:
# 2.0.6 neben 2.1.0). "find -print -quit" nahm davon irgendeinen, in undefinierter
# Reihenfolge -- der Waechter pruefte damit ein Paket, das dieser Bau gar nicht
# erzeugt hat. Massstab ist die Produktversion aus der in diesem Lauf erzeugten
# Aufstellung; gewaehlt wird die Paketdatei, deren NAME diese Version traegt.
# Weder Zeitstempel noch alphabetische Reihenfolge -- beide sind Zufall, kein Beleg.
# Kein Treffer oder mehr als einer ist ein benannter Abbruch mit Nennung ALLER
# gefundenen Dateien: ein Rueckfall auf irgendeinen Treffer waere genau der stille
# Fehlgriff, der hier behoben wird.
# $1 Verzeichnis, $2 Endung ohne Punkt (deb/rpm). Ergebnis steht in $PAKET_GEWAEHLT.
PAKET_GEWAEHLT=""
paket_dieses_baus_waehlen() {
    local verzeichnis="$1" endung="$2"
    local alle passende anzahl_alle anzahl_passend
    PAKET_GEWAEHLT=""
    alle=$(find "$verzeichnis" -maxdepth 1 -name "*.$endung" -type f 2>/dev/null | sort)
    anzahl_alle=$(printf '%s' "$alle" | grep -c . || true)
    if [ "$anzahl_alle" -eq 0 ]; then
        echo "      FEHLER: kein .$endung unter $verzeichnis gefunden."
        exit 1
    fi
    # Die Version muss als eigenes Namensfeld vorkommen, nicht als Teilzeichenkette:
    # sonst wuerde "2.1.0" auch in "12.1.05" treffen. Trenner sind '_' (deb:
    # CernisPro_2.1.0_amd64.deb) und '-' (rpm: CernisPro-2.1.0-1.x86_64.rpm).
    passende=$(printf '%s\n' "$alle" | grep -E "[_-]${PRODUKTVERSION//./\\.}[_-]" || true)
    anzahl_passend=$(printf '%s' "$passende" | grep -c . || true)
    if [ "$anzahl_passend" -ne 1 ]; then
        if [ "$anzahl_passend" -eq 0 ]; then
            echo "      FEHLER: unter $verzeichnis traegt KEINE .$endung-Datei die Produktversion $PRODUKTVERSION dieses Laufs."
        else
            echo "      FEHLER: unter $verzeichnis tragen $anzahl_passend .$endung-Dateien die Produktversion $PRODUKTVERSION dieses Laufs - die Wahl waere mehrdeutig."
        fi
        echo "        Produktversion dieses Laufs: $PRODUKTVERSION (aus $LIZENZ_JSON)"
        echo "        gefundene .$endung-Dateien ($anzahl_alle):"
        while IFS= read -r fund; do
            echo "          $fund"
        done <<< "$alle"
        echo "        Es wird KEIN anderes Paket ersatzweise geprueft: der Waechter"
        echo "        soll das Erzeugnis DIESES Baus belegen, nicht irgendeines."
        exit 1
    fi
    PAKET_GEWAEHLT="$passende"
}

paket_dieses_baus_waehlen "$BUNDLE_DIR/deb" "deb"
DEB_PAKET="$PAKET_GEWAEHLT"
command -v dpkg-deb >/dev/null 2>&1 || { echo "      FEHLER: dpkg-deb fehlt - die Beilage im .deb ist nicht pruefbar. Bitte: sudo apt install dpkg"; exit 1; }
echo "      Geprueft wird: $DEB_PAKET"
DEB_WORK=$(mktemp -d)
WAECHTER_TMP="$WAECHTER_TMP $DEB_WORK"
dpkg-deb -x "$DEB_PAKET" "$DEB_WORK"
for eintrag in "${DEB_ERWARTET[@]}"; do
    beilage_pruefen "$DEB_WORK" "${eintrag%%:*}" "${eintrag#*:}" "$DEB_PAKET" "deb"
done
laufzeitfund_pruefen "$DEB_WORK" "$DEB_PAKET" "deb"

paket_dieses_baus_waehlen "$BUNDLE_DIR/rpm" "rpm"
RPM_PAKET="$PAKET_GEWAEHLT"
# bsdtar aus libarchive-tools entpackt rpm unmittelbar und braucht dafuer kein
# zweites Werkzeug (rpm2cpio benoetigte zusaetzlich cpio, das in Debian nicht
# zum Grundsystem gehoert).
command -v bsdtar >/dev/null 2>&1 || { echo "      FEHLER: bsdtar fehlt - die Beilage im .rpm ist nicht pruefbar. Bitte: sudo apt install libarchive-tools"; exit 1; }
echo "      Geprueft wird: $RPM_PAKET"
RPM_WORK=$(mktemp -d)
WAECHTER_TMP="$WAECHTER_TMP $RPM_WORK"
bsdtar -x -f "$RPM_PAKET" -C "$RPM_WORK"
for eintrag in "${RPM_ERWARTET[@]}"; do
    beilage_pruefen "$RPM_WORK" "${eintrag%%:*}" "${eintrag#*:}" "$RPM_PAKET" "rpm"
done
laufzeitfund_pruefen "$RPM_WORK" "$RPM_PAKET" "rpm"

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
# EINE Versionsquelle im ganzen Skript: die in [7b/8] aus der erzeugten
# Aufstellung gelesene PRODUKTVERSION. Frueher stand hier eine ZWEITE
# Leseoperation direkt aus tauri.conf.json. Wichen beide voneinander ab, waere
# das ein Versionsfehler -- und genau diese Stelle haette ihn stillschweigend
# ueberdeckt: der Waechter haette das Paket der einen Version geprueft, und auf
# dem Schreibtisch waere es unter dem Dateinamen der anderen gelandet.
VERSION="$PRODUKTVERSION"
DEST="$HOME/Desktop"; mkdir -p "$DEST"
# Eingesammelt wird GENAU das Paket, das der Waechter in [7b/8] geprueft hat --
# nicht erneut per "find -print -quit" gesucht. Sonst koennte ein Altbestand aus
# dem Bundle-Verzeichnis unter dem Dateinamen der NEUEN Version auf dem
# Schreibtisch landen, und der gruene Waechter haette dafuer gar nicht gegolten.
cp "$DEB_PAKET" "$DEST/cernis-pro_${VERSION}_amd64.deb"
echo "      -> $DEST/cernis-pro_${VERSION}_amd64.deb (Quelle: $DEB_PAKET)"

echo ""
echo "============================================"
echo " BUILD ABGESCHLOSSEN (Version $VERSION)"
echo "============================================"
echo "Hinweis: deb-postinst.sh setzt nach Installation automatisch"
echo "  setcap cap_net_raw+eip /usr/bin/cernis-sniffd"
