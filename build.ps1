# ============================================================
#  CERNIS PRO - Windows Build Script (MSVC, x64 Standard)
#  Ergebnis: NSIS-Installer (Version aus tauri.conf.json)
#  Baut BEIDE Binaries (cernis-backend + cernis-sniffd, ADR 0041)
#  gegen den .venv-Python (uv) und bundelt via Tauri.
#  Aufruf: .\build.ps1
#
#  Spiegelbild von build-linux.sh fuer Windows. Das Ziel-Triple ist
#  NICHT hartkodiert, sondern kommt aus CERNIS_BUILD_TRIPLE (Default
#  x64) -- so laeuft dasselbe Skript unveraendert fuer Windows ARM
#  und im CI. Architektur, VS-Argument und Versions-Suffix werden
#  aus dem Triple ABGELEITET, nie separat gepflegt (der Architektur-
#  Widerspruch des v1-Skripts entfaellt damit).
# ============================================================

# Konsistente Fehlerbehandlung: jeder Cmdlet-Fehler bricht ab. Externe
# Aufrufe (git/uv/npm/tauri) setzen $LASTEXITCODE, den wir nach jedem
# Aufruf zentral pruefen -- nicht wie im v1-Skript teils manuell, teils
# gar nicht.
$ErrorActionPreference = "Stop"

# Alle Pfade absolut aus dem Skript-Verzeichnis ableiten. PowerShell 5.1:
# $PSScriptRoot ist hier verlaesslich der Ordner dieses Skripts.
$SCRIPT_DIR   = $PSScriptRoot
$BACKEND_DIR  = Join-Path $SCRIPT_DIR "backend"
$FRONTEND_DIR = Join-Path $SCRIPT_DIR "frontend"
$TAURI_SRC    = Join-Path $SCRIPT_DIR "src-tauri"

# Ziel-Triple wie build-linux.sh: Umgebungsvariable, sonst Default. Der
# Windows-Default ist x64 (die Specs sind x64) -- das v1-ARM64-Triple war
# ein Fehler.
$TRIPLE = if ($env:CERNIS_BUILD_TRIPLE) { $env:CERNIS_BUILD_TRIPLE } else { "x86_64-pc-windows-msvc" }

# Architektur AUS dem Triple ableiten (nicht separat hardkodieren). Aus dem
# Triple folgen DREI Werte, bewusst in getrennten Variablen:
#   ARCH         -- Anzeige/Architektur-Kuerzel, speist auch VCVARS_ARCH.
#   VCVARS_ARCH  -- Argument fuer vcvarsall.bat; kennt NUR x64/arm64.
#   VERSION_ARCH -- Suffix in der Build-Version (2.0.0+<VERSION_ARCH>.<sha>).
# Zwei getrennte Kuerzel, weil beide Werte verschiedene Fragen beantworten:
# vcvarsall versteht ausschliesslich "x64"/"arm64", waehrend das Versions-
# Suffix zusaetzlich die PLATTFORM nennen muss -- sonst ist "2.0.5+x64.<sha>"
# nicht von einem Linux- oder macOS-Build derselben Architektur unterscheidbar.
# Darum "winx64"/"winarm64" wie in den Windows-CI-Ablaeufen.
switch -Wildcard ($TRIPLE) {
    "x86_64-*" { $ARCH = "x64";   $VCVARS_ARCH = "x64";   $VERSION_ARCH = "winx64" }
    "aarch64-*" { $ARCH = "arm64"; $VCVARS_ARCH = "arm64"; $VERSION_ARCH = "winarm64" }
    default {
        Write-Host "FEHLER: Unbekanntes Triple '$TRIPLE' -- kann Architektur nicht ableiten." -ForegroundColor Red
        exit 1
    }
}

# Bricht mit klarer Meldung ab, wenn der letzte externe Aufruf != 0 lieferte.
function Assert-LastExit {
    param([string]$Was)
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FEHLER: $Was (Exit-Code $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
}

# PyInstaller/altgraph zeigt bei der scapy-Modulanalyse einen nicht-
# deterministischen Fehler ("Graph object does not support item assignment");
# ein erneuter Lauf geht in aller Regel durch. Darum jeden PyInstaller-Aufruf
# bis zu 3-mal versuchen. Schlaegt der dritte Versuch fehl, bricht das Skript
# mit Fehler ab (kein stiller Erfolg). Lauf gegen die .venv per 'uv run',
# nie gegen blankes python.
function Invoke-PyInstallerRetry {
    param([string]$Spec, [string]$Out)
    foreach ($attempt in 1, 2, 3) {
        Write-Host "      PyInstaller-Versuch $attempt/3: $Spec"
        # PS 5.1 mit ErrorActionPreference=Stop wertet Fortschrittsmeldungen
        # externer Tools auf stderr als NativeCommandError -> Abbruch. Darum um
        # den externen Aufruf herum auf Continue schalten, danach zurueck auf
        # Stop. Der Exit-Code wird ueber $LASTEXITCODE geprueft.
        $ErrorActionPreference = "Continue"
        uv run pyinstaller $Spec --noconfirm
        $ErrorActionPreference = "Stop"
        if (($LASTEXITCODE -eq 0) -and (Test-Path $Out)) { return }
        Write-Host "      Versuch $attempt fehlgeschlagen."
    }
    Write-Host "FEHLER: PyInstaller ($Spec) nach 3 Versuchen fehlgeschlagen" -ForegroundColor Red
    exit 1
}

Write-Host "============================================"
Write-Host " CERNIS PRO Windows $ARCH Build"
Write-Host " Ziel-Triple: $TRIPLE"
Write-Host " Arbeitsverzeichnis: $SCRIPT_DIR"
Write-Host "============================================"

# ── Schritt 0: VS Build Tools Umgebung ──────────────────────
# PyInstaller und Tauri (Rust/MSVC-Linker) brauchen die MSVC-Umgebung.
# Visual Studio 2022 BuildTools ist als vorhanden bestaetigt; das VS-Argument
# (x64/arm64) kommt aus dem Triple, nicht separat gepflegt.
Write-Host ""
Write-Host "[0/6] VS Build Tools Umgebung initialisieren ($VCVARS_ARCH)..."

# Ist die MSVC-Umgebung bereits gesetzt (VSINSTALLDIR vorhanden), NICHT erneut
# per vcvarsall einrichten -- sonst wuerde eine schon korrekt gesetzte Umgebung
# ueberschrieben. Im CI richtet ilammy/msvc-dev-cmd PATH/LIB/INCLUDE auf das
# real vorhandene SDK ein (VSINSTALLDIR gesetzt) und darf nicht durch vcvarsall
# ersetzt werden, das LIB auf eine fehlende SDK-Version zeigt (LNK1181). Lokal
# auf der Win11-VM ist VSINSTALLDIR in einer frischen Shell nicht gesetzt --
# dort laeuft der vcvarsall-Block unveraendert wie bisher.
if ($env:VSINSTALLDIR) {
    Write-Host "      VS Build Tools: Umgebung bereits gesetzt (VSINSTALLDIR vorhanden), vcvarsall uebersprungen"
}
else {

# vcvarsall.bat finden, OHNE den Pfad hart zu verdrahten: die lokale VM hat
# die Edition "BuildTools", der GitHub-Runner eine andere Edition an einem
# anderen Ort -- ein hartkodierter Pfad bricht auf der jeweils anderen Maschine
# (und ein zweiter hartkodierter Pfad waere derselbe Fehler nur ein zweites
# Mal). Darum vswhere befragen: dieses von Microsoft mitgelieferte Werkzeug
# liegt an einem festen, garantierten Ort und findet JEDE VS-Installation
# edition- und ortsunabhaengig. Aus dem gemeldeten Installationsstamm leiten
# wir vcvarsall.bat ab. Faellt vswhere aus oder findet nichts, versuchen wir
# als Rueckfall den bisher bekannten lokalen BuildTools-Pfad -- und erst wenn
# auch der fehlt, brechen wir mit klarer Meldung ab.
$vcvarsall = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    # -latest neueste Installation, -products * auch die Edition BuildTools,
    # -property installationPath liefert den Installationsstamm (ohne trailing
    # Zeilenumbruch dank .Trim()). Schlaegt vswhere fehl, bleibt $vsInstall leer
    # und wir fallen unten auf den bekannten Pfad zurueck.
    $vsInstall = (& $vswhere -latest -products * -property installationPath 2>$null | Select-Object -First 1)
    if ($vsInstall) {
        $candidate = Join-Path $vsInstall.Trim() "VC\Auxiliary\Build\vcvarsall.bat"
        if (Test-Path $candidate) { $vcvarsall = $candidate }
    }
}
if (-not $vcvarsall) {
    # Rueckfall: der bisher bekannte lokale BuildTools-Pfad.
    $fallback = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
    if (Test-Path $fallback) { $vcvarsall = $fallback }
}
if (-not $vcvarsall) {
    Write-Host "FEHLER: vcvarsall.bat nicht gefunden (weder via vswhere noch am bekannten BuildTools-Pfad)." -ForegroundColor Red
    Write-Host "Bitte Visual Studio Build Tools 2022 installieren." -ForegroundColor Red
    exit 1
}

# vcvarsall.bat setzt Umgebungsvariablen nur in seiner eigenen cmd-Instanz.
# Darum in cmd aufrufen, danach 'set' abgreifen und die Variablen in den
# aktuellen PowerShell-Prozess uebernehmen -- sonst sieht PyInstaller/Tauri
# die MSVC-Toolchain nicht.
#
# Den urspruenglichen PATH VOR dem cmd-Aufruf sichern: vcvarsall liefert per
# 'set' einen PATH, der nur die MSVC-/SDK-Werkzeuge enthaelt, NICHT aber die
# uebrigen Eintraege der Nutzerumgebung. Wuerden wir diesen PATH stur
# uebernehmen (wie alle anderen Variablen), verschwaenden node, git, uv und npm
# aus dem PATH des laufenden Prozesses -- der Frontend-Schritt (npm/node) wuerde
# dann mit "node nicht gefunden" scheitern, obwohl node installiert ist. Darum
# wird der PATH weiter unten gesondert GEMERGT statt ersetzt. Bitte nicht auf
# stures Ueberschreiben zurueckdrehen.
$originalPath = $env:PATH

$vsEnv = cmd /c "`"$vcvarsall`" $VCVARS_ARCH >nul 2>&1 && set" | Where-Object { $_ -match '=' }

# LASTEXITCODE ist hier NICHT belastbar: zwischen dem cmd-Aufruf und dieser
# Zeile liegt die Pipeline mit Where-Object, deren Exit-Code $LASTEXITCODE
# ueberschreibt -- der Rueckgabewert von cmd/vcvarsall geht verloren. Statt-
# dessen inhaltlich pruefen: es muessen Variablen zurueckgekommen sein UND eine
# fuer MSVC charakteristische Variable muss gesetzt sein. Als Marker dient
# VSINSTALLDIR -- diese Variable setzt ausschliesslich vcvarsall (Wurzel der
# VS-Installation), sie existiert in einer frischen Shell nicht und wird
# unabhaengig von der Ziel-Architektur (x64/arm64) gesetzt. Fehlt sie, ist
# vcvarsall nicht korrekt durchgelaufen.
$vsEnvMap = @{}
foreach ($line in $vsEnv) {
    $parts = $line -split '=', 2
    if ($parts.Count -eq 2) { $vsEnvMap[$parts[0]] = $parts[1] }
}
if (($vsEnvMap.Count -eq 0) -or (-not $vsEnvMap.ContainsKey("VSINSTALLDIR"))) {
    Write-Host "FEHLER: vcvarsall.bat ($VCVARS_ARCH) lieferte keine gueltige MSVC-Umgebung (VSINSTALLDIR fehlt)" -ForegroundColor Red
    exit 1
}

foreach ($name in $vsEnvMap.Keys) {
    if ($name -ieq "PATH") {
        # PATH mergen statt ersetzen: die von vcvarsall gelieferten Eintraege
        # zuerst (damit der MSVC-Linker seine Werkzeuge vorrangig findet),
        # danach der urspruengliche PATH (damit node/git/uv/npm erreichbar
        # bleiben). Dubletten (case-insensitiv, Windows-Pfade) werden dabei
        # ausgelassen, um einen aufgeblaehten PATH zu vermeiden.
        $seen = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
        $merged = New-Object System.Collections.Generic.List[string]
        foreach ($entry in (($vsEnvMap[$name] + ';' + $originalPath) -split ';')) {
            if (($entry -ne '') -and $seen.Add($entry)) { $merged.Add($entry) }
        }
        [System.Environment]::SetEnvironmentVariable("PATH", ($merged -join ';'), "Process")
    }
    else {
        [System.Environment]::SetEnvironmentVariable($name, $vsEnvMap[$name], "Process")
    }
}
Write-Host "      VS Build Tools ${VCVARS_ARCH}: OK"

}  # Ende else: vcvarsall-Block nur, wenn VSINSTALLDIR nicht bereits gesetzt war

# ── Schritt 1: Python-Abhaengigkeiten (uv, gegen .venv) ─────
# Einzige Wahrheit ist uv.lock -- kein pip, kein requirements.txt. '--locked'
# erzwingt exakt die gelockten Versionen (Fehler statt stiller Aktualisierung).
# '--group dev' zieht PyInstaller mit rein (steht in pyproject.toml unter
# dependency-groups.dev).
Write-Host ""
Write-Host "[1/6] Python-Abhaengigkeiten (uv sync --locked --group dev)..."
Push-Location $SCRIPT_DIR
$ErrorActionPreference = "Continue"
uv sync --locked --group dev
$ErrorActionPreference = "Stop"
Assert-LastExit "uv sync"
Pop-Location
Write-Host "      OK"

# ── Schritt 1b: Build-Version erzeugen ──────────────────────
# config.py liest os.environ NICHT -- es importiert diese Datei. PyInstaller
# friert sie ein, damit die installierte App die volle Version kennt. Format
# wie im Linux-Workflow: 2.0.0+<VERSION_ARCH>.<sha> (winx64/winarm64), oben aus
# dem Triple abgeleitet -- NICHT $ARCH, das speist die Compiler-Umgebung.
# Der v1-Fehler "nur 2.0.0 ohne SHA" entfaellt, weil die Datei jetzt VOR dem
# PyInstaller-Lauf entsteht.
Write-Host ""
Write-Host "[1b/6] Build-Version erzeugen (_build_version.py)..."
$ErrorActionPreference = "Continue"
$SHORT_SHA = (git -C $SCRIPT_DIR rev-parse --short=7 HEAD).Trim()
$ErrorActionPreference = "Stop"
Assert-LastExit "git rev-parse"
# Produktversion aus pyproject.toml ableiten (Quelle der Wahrheit) -- nicht fest
# eintippen, damit der naechste Versionsbump hier automatisch ankommt.
$pyprojectPfad = Join-Path $SCRIPT_DIR "pyproject.toml"
$PRODUCT_VERSION = (Select-String -Path $pyprojectPfad -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches.Groups[1].Value
if (-not $PRODUCT_VERSION) { throw "Produktversion aus pyproject.toml nicht lesbar" }
$BUILD_VERSION = "$PRODUCT_VERSION+$VERSION_ARCH.$SHORT_SHA"
Write-Host "      Build-Version: $BUILD_VERSION"
$buildVersionFile = Join-Path $BACKEND_DIR "infrastructure\_build_version.py"
$buildVersionContent = @"
"""Im CI erzeugte Build-Version. Nicht committet (siehe .gitignore)."""

BUILD_VERSION = "$BUILD_VERSION"
"@
# Ohne BOM schreiben -- eine BOM am Dateianfang stoert den Python-Import.
[System.IO.File]::WriteAllText($buildVersionFile, $buildVersionContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "      OK - $buildVersionFile"

# ── Schritt 2: Frontend bauen ────────────────────────────────
# Auf Windows immer npm.cmd (Execution-Policy blockt 'npm'). 'npm ci' statt
# 'npm install' -- installiert exakt das Lockfile, nicht irgendwas Kompatibles.
Write-Host ""
Write-Host "[2/6] Frontend bauen (npm.cmd ci + build)..."
Push-Location $FRONTEND_DIR
$ErrorActionPreference = "Continue"
npm.cmd ci
$ErrorActionPreference = "Stop"
Assert-LastExit "npm ci (frontend)"
$ErrorActionPreference = "Continue"
npm.cmd run build
$ErrorActionPreference = "Stop"
Assert-LastExit "npm run build (frontend)"
Pop-Location
Write-Host "      OK - dist/ erstellt"

# ── Schritt 3: Backend-Binary (cernis-backend) ───────────────
# dist/ und build/ NUR HIER EINMAL loeschen -- nicht erneut vor dem sniffd-
# Lauf, sonst wird das gerade gebaute Backend-Binary wieder geloescht.
Write-Host ""
Write-Host "[3/6] Backend-Binary erstellen (PyInstaller)..."
Push-Location $BACKEND_DIR
if (Test-Path "dist")  { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
# Verwaiste .pyc (Reste geloeschter Module) lassen PyInstallers Modulanalyse
# DETERMINISTISCH scheitern ("TypeError: required field 'id' missing from Name").
# Zwei sich ergaenzende Sicherungen, beide noetig: das .py-glob in der Spec haelt
# sie aus dem Bundle, dieses Loeschen haelt die Analyse davon ab, ueber sie zu
# stolpern. Alle __pycache__-Verzeichnisse unterhalb von backend rekursiv weg.
Get-ChildItem -Path $BACKEND_DIR -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }

$BACKEND_BIN = Join-Path $BACKEND_DIR "dist\cernis-backend.exe"
Invoke-PyInstallerRetry -Spec "cernis_windows.spec" -Out $BACKEND_BIN
Pop-Location
Write-Host "      OK - $BACKEND_BIN"

# ── Schritt 3b: Sniff-Helfer-Binary (cernis-sniffd) ─────────
# dist/build hier bewusst NICHT loeschen: enthaelt bereits cernis-backend.
Write-Host ""
Write-Host "[3b/6] Sniff-Helfer-Binary erstellen (cernis-sniffd)..."
Push-Location $BACKEND_DIR
$SNIFFD_BIN = Join-Path $BACKEND_DIR "dist\cernis-sniffd.exe"
Invoke-PyInstallerRetry -Spec "cernis_sniffd_windows.spec" -Out $SNIFFD_BIN
Pop-Location
Write-Host "      OK - $SNIFFD_BIN"

# ── Schritt 3c: Sniff-Helfer verifizieren ───────────────────
# Der schlanke Helfer darf KEINE Backend-only-Deps enthalten. build-linux.sh
# macht das mit 'strings | grep'; strings gibt es unter Windows nicht. Aequi-
# valent: Select-String mit -Encoding Byte-Fallback ist unhandlich -- statt-
# dessen die Binaerdatei als Latin1 einlesen (jedes Byte -> ein Zeichen,
# verlustfrei) und darin case-insensitiv nach den Markern suchen. Das findet
# eingebettete ASCII-Zeichenketten genau wie 'strings'. Fund = WARNUNG (kein
# harter Abbruch), exakt wie im Linux-Vorbild.
Write-Host ""
Write-Host "[3c/6] Sniff-Helfer verifizieren (keine Backend-only-Deps)..."
$sniffdText = [System.IO.File]::ReadAllText($SNIFFD_BIN, [System.Text.Encoding]::GetEncoding("ISO-8859-1"))
$leak = $false
foreach ($forbidden in "fastapi", "uvicorn", "starlette", "reportlab") {
    if ($sniffdText -imatch [regex]::Escape($forbidden)) {
        Write-Host "      WARNUNG: '$forbidden' im sniffd-Binary" -ForegroundColor Yellow
        $leak = $true
    }
}
if (-not $leak) { Write-Host "      OK - schlank" }

# ── Schritt 3d: Lizenzaufstellung erzeugen ──────────────────
# Spiegelbild von build-linux.sh Schritt [5/8]. Der Zeitpunkt ist bindend und
# derselbe wie dort: NACH den PyInstaller-Laeufen (3/3b) und VOR dem Tauri-
# Build (5). Die mitgelieferten nativen Bibliotheken stammen aus PyInstallers
# Abhaengigkeitsanalyse und stehen erst jetzt fest; in die Binaries koennen sie
# nicht mehr hinein, deshalb geht die Aufstellung ueber bundle.resources ins
# Paket. src-tauri/tauri.conf.json fuehrt lizenzaufstellung.json und LICENSE
# dort bereits -- keine Aenderung noetig.
#
# Der Schritt traegt 3d und nicht eine eigene Hauptnummer: das Skript nummeriert
# nachtraeglich eingefuegte Teilschritte seit jeher mit Buchstaben (1b, 3b, 3c).
# So bleibt die Gesamtzahl 6 richtig und keine der zehn bestehenden Zaehlerzeilen
# muss angefasst werden -- eine Durchnummerierung auf /7 haette alle zehn
# geaendert, ohne dass eine davon inhaltlich falsch gewesen waere.
# ── Schritt 3cc: Wurzel-Abhaengigkeiten installieren ────────
# Die Reihenfolge ist bindend und darf NICHT zurueckgedreht werden: der Sammler
# in [3d/6] liest die AUFGELOESTEN Wurzel-Abhaengigkeiten ueber
# 'npm ls --omit=dev' im Wurzelverzeichnis. Ohne node_modules an der Wurzel
# loest sich keine einzige der erklaerten produktiven Abhaengigkeiten auf, und
# der npm-Waechter des Sammlers bricht ab.
#
# Anlass ist Befund 25, gemessen am Linux-Bau 30842765403 auf GitHub Actions.
# Dieses Skript war gleichermassen betroffen: das Wurzel-Install stand frueher
# erst in [5/6], unmittelbar vor dem Tauri-Bau -- also NACH dem Sammler. Auf
# Maschinen mit einem node_modules aus frueheren Laeufen faellt das nicht auf,
# auf einer frischen sofort.
#
# Das Install steht nur noch HIER, nicht mehr zusaetzlich in [5/6]: zweimal
# ausgefuehrt kostet es Zeit, ohne etwas zu aendern. Der Tauri-Bau findet die
# CLI unveraendert vor, denn zwischen hier und [5/6] wird an node_modules
# nichts angefasst.
#
# Aufrufform unveraendert uebernommen: npm.cmd (Execution-Policy blockt 'npm')
# und 'ci' statt 'install' -- installiert exakt das Lockfile, nicht irgendwas
# Kompatibles.
#
# Der Schritt traegt 3cc und nicht eine eigene Hauptnummer: das Skript
# nummeriert nachtraeglich eingefuegte Teilschritte seit jeher mit Buchstaben
# (1b, 3b, 3c, 3d). So bleibt die Gesamtzahl 6 richtig und keine bestehende
# Zaehlerzeile muss angefasst werden.
Write-Host ""
Write-Host "[3cc/6] Wurzel-Abhaengigkeiten installieren (npm.cmd ci, fuer Sammler und Tauri-CLI)..."
Push-Location $SCRIPT_DIR
$ErrorActionPreference = "Continue"
npm.cmd ci
$ErrorActionPreference = "Stop"
Assert-LastExit "npm ci (tauri)"
Pop-Location
Write-Host "      OK"

Write-Host ""
Write-Host "[3d/6] Lizenzaufstellung erzeugen (inkl. nativer Bibliotheken)..."
$LIZENZ_JSON = Join-Path $TAURI_SRC "lizenzaufstellung.json"
# --zielplattform: die Plattform, FUER die gebaut wird. Der Sammler leitet
# daraus das Rust-Ziel und die Endungen der nativen Bibliotheken ab, statt sie
# aus der laufenden Maschine zu raten. Aus dem Triple abgeleitet wie ARCH oben,
# damit ein ARM64-Bau nicht stillschweigend die x64-Aufstellung erzeugt. Ein
# unbekanntes Triple ist ein Abbruch, kein Rueckfall auf einen Vorgabewert.
switch -Wildcard ($TRIPLE) {
    "x86_64-*"  { $ZIELPLATTFORM = "windows-x86_64" }
    "aarch64-*" { $ZIELPLATTFORM = "windows-aarch64" }
    default {
        Write-Host "FEHLER: Unbekanntes Triple '$TRIPLE' -- kann Zielplattform nicht ableiten." -ForegroundColor Red
        exit 1
    }
}
$ErrorActionPreference = "Continue"
uv run python (Join-Path $SCRIPT_DIR "scripts\gen_license_manifest.py") $LIZENZ_JSON `
    --wurzel $SCRIPT_DIR `
    --binaerverzeichnis (Join-Path $BACKEND_DIR "dist") `
    --zielplattform $ZIELPLATTFORM
$ErrorActionPreference = "Stop"
Assert-LastExit "gen_license_manifest.py"
# Kein stiller Fallback: eine fehlende oder leere Aufstellung bricht den Bau ab
# (build-linux.sh Zeile 87). 'Length -gt 0' ist das PowerShell-Gegenstueck zu
# 'test -s'; Test-Path allein wuerde eine leere Datei durchgehen lassen.
if (-not (Test-Path $LIZENZ_JSON) -or ((Get-Item $LIZENZ_JSON).Length -eq 0)) {
    Write-Host "FEHLER: $LIZENZ_JSON fehlt oder ist leer" -ForegroundColor Red
    exit 1
}
# Die Wurzel-LICENSE kommt ueber dieselbe Ressourcenliste ins Paket. Kopie, das
# Original bleibt unberuehrt (build-linux.sh Zeile 89).
$LIZENZ_DATEI = Join-Path $TAURI_SRC "LICENSE"
Copy-Item (Join-Path $SCRIPT_DIR "LICENSE") $LIZENZ_DATEI -Force
if (-not (Test-Path $LIZENZ_DATEI) -or ((Get-Item $LIZENZ_DATEI).Length -eq 0)) {
    Write-Host "FEHLER: $LIZENZ_DATEI fehlt oder ist leer" -ForegroundColor Red
    exit 1
}
Write-Host "      OK"

# ── Schritt 4: Binaries fuer Tauri bereitstellen ────────────
# Tauri externalBin erwartet <name>-<triple>.exe neben src-tauri/; zusaetzlich
# legen wir sie ins Release-Verzeichnis des Triples (wie build-linux.sh).
Write-Host ""
Write-Host "[4/6] Binaries fuer Tauri bereitstellen (Triple $TRIPLE)..."
Copy-Item $BACKEND_BIN (Join-Path $TAURI_SRC "cernis-backend-$TRIPLE.exe") -Force
Copy-Item $SNIFFD_BIN  (Join-Path $TAURI_SRC "cernis-sniffd-$TRIPLE.exe")  -Force

$TAURI_RELEASE = Join-Path $TAURI_SRC "target\$TRIPLE\release"
New-Item -ItemType Directory -Path $TAURI_RELEASE -Force | Out-Null
Copy-Item $BACKEND_BIN (Join-Path $TAURI_RELEASE "cernis-backend.exe") -Force
Copy-Item $SNIFFD_BIN  (Join-Path $TAURI_RELEASE "cernis-sniffd.exe")  -Force
Write-Host "      OK"

# ── Schritt 5: Tauri-Build (NSIS-Installer) ─────────────────
# Das 'npm.cmd ci' fuer die Tauri-CLI (Lockfile-treu) steht seit Befund 25 in
# [3cc/6] und NICHT mehr hier: der Sammler in [3d/6] braucht es bereits. Ein
# zweiter Lauf an dieser Stelle waere wirkungslos, denn zwischendurch wird an
# node_modules nichts angefasst. Tauri via 'npx tauri build --target $TRIPLE'
# aufrufen -- das Triple kommt vom Skript, so wie build-linux.sh es macht; das
# Root-Skript build-tauri traegt darum kein --target mehr. npx.cmd (Windows).
# Der Ziel-Ordner haengt so am Triple und passt zu den Kopier-Pfaden oben.
Write-Host ""
Write-Host "[5/6] Tauri-Build (NSIS-Installer, Target $TRIPLE)..."
Push-Location $SCRIPT_DIR
$ErrorActionPreference = "Continue"
npx.cmd tauri build --target $TRIPLE
$ErrorActionPreference = "Stop"
Assert-LastExit "tauri build"
Pop-Location
Write-Host "      OK"

# ── Schritt 5b: Waechter Vorhandensein der Beilage ──────────
# Warum ueberhaupt: ein Bau kann mit RC=0 durchlaufen, OHNE dass die Beilage im
# Erzeugnis ankommt -- auf macOS ist genau das passiert (stille Array-Ersetzung
# der bundle.resources nach RFC 7396), und gefunden wurde es von Hand, nicht vom
# Bau. Ein gruener Bau belegt eben nicht seinen Inhalt.
#
# Die Stelle ist bindend: NACH Schritt [5/6] und VOR Schritt [6/6]. Der
# Installer liegt hier fertig vor -- geprueft wird also am ECHTEN Erzeugnis,
# nicht am Quellverzeichnis und nicht an dem, was der Bau abgelegt zu haben
# glaubt. Und weil das Einsammeln erst danach kommt, kann ein Installer mit
# fehlender Beilage nicht als Ergebnis durchgehen.
#
# WARUM HIER GESUCHT UND NICHT AN EINEM PFAD GEPRUEFT WIRD: der Ablageort im
# Installationsverzeichnis ist NICHT belegt. Gemessen ist nur, dass das
# NSIS-Template die Ressourcen mit  File /a "/oname=<relativer Name>"  unterhalb
# von $INSTDIR ablegt; welcher relative Name das ist, entsteht erst im
# kompilierten Bundler und steht weder in src-tauri/tauri.conf.json noch im
# Klartext in der Tauri-CLI. Einen Pfad zu RATEN waere schlimmer als keine
# Pruefung: ein falsch geratener Pfad faellt bei jedem korrekten Bau. Darum wird
# im Installer nach dem DATEINAMEN gesucht, ohne Annahme ueber sein Verzeichnis.
#
# 7-Zip ist dafuer Voraussetzung und kein Rueckfall: fehlt es, bricht der Bau ab,
# statt ersatzweise das Pack-Verzeichnis zu pruefen. Das Pack-Verzeichnis zeigt
# nur, was hineingehen SOLL -- und genau diese Luecke zwischen "soll" und "kommt
# an" ist der Grund fuer diesen Waechter.
#
# Der Waechter prueft NUR und legt NICHTS nach: ein nachtraegliches Einfuegen in
# den fertigen Installer waere ein stiller Rueckfall auf ein Erzeugnis, das der
# Bau so nie hergestellt hat.
#
# Der Schritt traegt 5b und nicht eine eigene Hauptnummer: das Skript nummeriert
# nachtraeglich eingefuegte Teilschritte seit jeher mit Buchstaben (1b, 3b, 3c,
# 3d). So bleibt die Gesamtzahl 6 richtig und keine bestehende Zaehlerzeile muss
# angefasst werden.
Write-Host ""
Write-Host "[5b/6] Beilage im gebauten Installer pruefen (Waechter)..."

$WAECHTER_NSIS_DIR = Join-Path $TAURI_SRC "target\$TRIPLE\release\bundle\nsis"
$WAECHTER_INSTALLER = Get-ChildItem -Path $WAECHTER_NSIS_DIR -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $WAECHTER_INSTALLER) {
    Write-Host "FEHLER: Kein NSIS-Installer gefunden in $WAECHTER_NSIS_DIR" -ForegroundColor Red
    Write-Host "  Ohne Erzeugnis ist die Beilage nicht pruefbar." -ForegroundColor Red
    exit 1
}
Write-Host "      Geprueft wird: $($WAECHTER_INSTALLER.FullName)"

# 7-Zip finden. Kein Rueckfall auf eine schwaechere Pruefung: fehlt das
# Werkzeug, ist der Inhalt des Installers unbekannt, und ein unbekannter Inhalt
# darf nicht als geprueft durchgehen.
$SIEBENZIP = $null
foreach ($kandidat in @(
    "$env:ProgramFiles\7-Zip\7z.exe",
    "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
)) {
    if ($kandidat -and (Test-Path $kandidat)) { $SIEBENZIP = $kandidat; break }
}
if (-not $SIEBENZIP) {
    $ausPfad = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($ausPfad) { $SIEBENZIP = $ausPfad.Source }
}
if (-not $SIEBENZIP) {
    Write-Host "FEHLER: 7-Zip (7z.exe) nicht gefunden - der Inhalt des NSIS-Installers" -ForegroundColor Red
    Write-Host "  ist damit nicht pruefbar. 7-Zip ist fuer den Windows-Bau Voraussetzung," -ForegroundColor Red
    Write-Host "  kein Zubehoer: ohne Inhaltspruefung koennte ein Installer ohne Beilage" -ForegroundColor Red
    Write-Host "  als Erfolg durchgehen." -ForegroundColor Red
    Write-Host "  Weg:  winget install 7zip.7zip     (oder https://7-zip.org)" -ForegroundColor Red
    exit 1
}

# Inhaltsverzeichnis des Installers auflisten, ohne zu installieren und ohne zu
# entpacken. '7z l -slt' liefert je Eintrag einen Block mit 'Path = ...' und
# 'Size = ...' -- daraus bauen wir Name -> groesste gefundene Groesse.
$ErrorActionPreference = "Continue"
$archivListe = & $SIEBENZIP l -slt -- $WAECHTER_INSTALLER.FullName 2>&1
$listeRC = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($listeRC -ne 0) {
    Write-Host "FEHLER: 7-Zip konnte den Installer nicht lesen (Exit $listeRC):" -ForegroundColor Red
    Write-Host ($archivListe -join "`n") -ForegroundColor Red
    Write-Host "  geprueftes Erzeugnis: $($WAECHTER_INSTALLER.FullName)" -ForegroundColor Red
    exit 1
}

# Eintraege einsammeln: Dateiname (ohne Verzeichnis, klein) -> groesste Groesse.
# Der Dateiname allein ist der Schluessel, weil der Ablageort im Installer nicht
# belegt ist -- siehe die Begruendung oben.
$gefunden = @{}
$aktuellerPfad = $null
foreach ($zeile in $archivListe) {
    $text = [string]$zeile
    if ($text -match '^Path = (.+)$') {
        $aktuellerPfad = $Matches[1].Trim()
    }
    elseif (($text -match '^Size = (\d+)\s*$') -and $aktuellerPfad) {
        $name = (Split-Path $aktuellerPfad -Leaf).ToLowerInvariant()
        $groesse = [int64]$Matches[1]
        if ((-not $gefunden.ContainsKey($name)) -or ($gefunden[$name].Groesse -lt $groesse)) {
            $gefunden[$name] = @{ Groesse = $groesse; Pfad = $aktuellerPfad }
        }
        $aktuellerPfad = $null
    }
}

# Jede erwartete Datei EINZELN und namentlich -- eine Sammelmeldung
# "irgendetwas fehlt" liesse offen, wonach zu suchen waere.
$beilageFehlt = $false
foreach ($erwartet in "lizenzaufstellung.json", "LICENSE") {
    $schluessel = $erwartet.ToLowerInvariant()
    if (-not $gefunden.ContainsKey($schluessel)) {
        Write-Host "      FEHLER: '$erwartet' fehlt im gebauten Installer." -ForegroundColor Red
        Write-Host "        erwarteter Ort:       im Installer, unterhalb des spaeteren"
        Write-Host "                              Installationsverzeichnisses (`$INSTDIR). Der genaue"
        Write-Host "                              relative Ablageort ist NICHT belegt, darum wurde"
        Write-Host "                              nach dem Dateinamen gesucht statt an einem Pfad."
        Write-Host "        geprueftes Erzeugnis: $($WAECHTER_INSTALLER.FullName)"
        Write-Host "        naechstliegende Ursache: fehlender oder falscher Eintrag unter"
        Write-Host "                              bundle.resources in src-tauri/tauri.conf.json."
        Write-Host "                              Es gibt fuer Windows kein tauri.windows.conf.json;"
        Write-Host "                              faende sich eines mit eigenem resources-Array, wuerde"
        Write-Host "                              es den Wert der Grundkonfiguration nach RFC 7396"
        Write-Host "                              vollstaendig ERSETZEN statt ihn zu ergaenzen."
        $beilageFehlt = $true
    }
    # Vorhandensein allein genuegt nicht: eine leere Beilage ist dasselbe wie
    # keine.
    elseif ($gefunden[$schluessel].Groesse -eq 0) {
        Write-Host "      FEHLER: '$erwartet' ist LEER im gebauten Installer (0 Bytes)." -ForegroundColor Red
        Write-Host "        gefunden als:         $($gefunden[$schluessel].Pfad)"
        Write-Host "        geprueftes Erzeugnis: $($WAECHTER_INSTALLER.FullName)"
        Write-Host "        naechstliegende Ursache: die Quelldatei unter src-tauri/ war beim"
        Write-Host "                              Tauri-Bau bereits leer -- siehe Schritt [3d/6]."
        $beilageFehlt = $true
    }
    else {
        Write-Host "      OK - $erwartet ($($gefunden[$schluessel].Groesse) Bytes, als $($gefunden[$schluessel].Pfad))"
    }
}

# Fehlt etwas, bricht der Bau ab: kein Warnhinweis, kein Weiterlaufen, kein
# Einsammeln.
if ($beilageFehlt) {
    Write-Host "      Der Bau wird abgebrochen. Es wird NICHTS nachgelegt und NICHTS" -ForegroundColor Red
    Write-Host "      repariert -- das waere ein stiller Rueckfall auf ein Erzeugnis, das" -ForegroundColor Red
    Write-Host "      der Bau so nie hergestellt hat." -ForegroundColor Red
    Write-Host "      Weg: Ursache oben beheben und neu bauen." -ForegroundColor Red
    exit 1
}

# ── Schritt 6: Installer einsammeln ─────────────────────────
# Version aus tauri.conf.json (Quelle der Wahrheit fuer die Produktversion).
# Kein Installer = FEHLER mit Abbruch -- ein Build ohne Ergebnis ist kein
# Erfolg (im v1-Skript nur eine Warnung).
Write-Host ""
Write-Host "[6/6] Installer einsammeln..."
$VERSION = (Get-Content (Join-Path $TAURI_SRC "tauri.conf.json") -Raw | ConvertFrom-Json).version

$NSIS_DIR = Join-Path $TAURI_SRC "target\$TRIPLE\release\bundle\nsis"
$INSTALLER = Get-ChildItem -Path $NSIS_DIR -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $INSTALLER) {
    Write-Host "FEHLER: Kein NSIS-Installer gefunden in $NSIS_DIR" -ForegroundColor Red
    exit 1
}
# Der Installer verbleibt immer im Bundle-Verzeichnis -- identisches
# CI-/Release-Verhalten auf lokaler VM wie auf dem GitHub-Runner. Der
# Nicht-gefunden-Fehler oben (exit 1) bleibt der einzige Abbruchgrund.
$FINAL_INSTALLER = $INSTALLER.FullName
Write-Host "      -> $FINAL_INSTALLER"

Write-Host ""
Write-Host "============================================"
Write-Host " BUILD ABGESCHLOSSEN (Version $VERSION, $ARCH)"
Write-Host " Build-Version: $BUILD_VERSION"
Write-Host " Installer: $FINAL_INSTALLER"
Write-Host "============================================"
