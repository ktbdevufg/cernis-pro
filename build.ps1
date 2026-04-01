# ============================================================
#  CERNIS PRO - Windows x64 Build Script
#  Plattform: Windows x64 (MSVC)
#  Ergebnis:  CernisPro_1.0.0_x64-setup.exe (NSIS Installer)
#
#  Aufruf: .\build.ps1
# ============================================================

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKEND_DIR = Join-Path $SCRIPT_DIR "backend"
$FRONTEND_DIR = Join-Path $SCRIPT_DIR "frontend"
$TAURI_DIR = $SCRIPT_DIR
$TAURI_SRC = Join-Path $SCRIPT_DIR "src-tauri"

Write-Host "============================================"
Write-Host " CERNIS PRO Windows x64 Build"
Write-Host " Arbeitsverzeichnis: $SCRIPT_DIR"
Write-Host "============================================"

# ── Schritt 0: VS Build Tools Umgebung ──────────────────────
Write-Host ""
Write-Host "[0/6] VS Build Tools Umgebung initialisieren..."

$vcvarsall = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvarsall)) {
    Write-Host "FEHLER: vcvarsall.bat nicht gefunden: $vcvarsall" -ForegroundColor Red
    Write-Host "Bitte Visual Studio Build Tools 2022 installieren." -ForegroundColor Red
    exit 1
}

# Import VS environment variables into PowerShell
$vsEnv = cmd /c "`"$vcvarsall`" x64 >nul 2>&1 && set" | Where-Object { $_ -match '=' }
foreach ($line in $vsEnv) {
    $parts = $line -split '=', 2
    [System.Environment]::SetEnvironmentVariable($parts[0], $parts[1], "Process")
}
Write-Host "      VS Build Tools x64: OK"

# ── Schritt 1: Python-Abhängigkeiten installieren ──────────
Write-Host ""
Write-Host "[1/6] Python-Abhängigkeiten installieren..."
Push-Location $BACKEND_DIR
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) { Write-Host "FEHLER: pip install fehlgeschlagen" -ForegroundColor Red; exit 1 }

# PyInstaller sicherstellen
pip install pyinstaller --quiet
Write-Host "      OK"
Pop-Location

# ── Schritt 2: Frontend bauen ────────────────────────────────
Write-Host ""
Write-Host "[2/6] Frontend bauen (npm)..."
Push-Location $FRONTEND_DIR
npm install --silent
if ($LASTEXITCODE -ne 0) { Write-Host "FEHLER: npm install fehlgeschlagen" -ForegroundColor Red; exit 1 }
npm run build
if ($LASTEXITCODE -ne 0) { Write-Host "FEHLER: npm run build fehlgeschlagen" -ForegroundColor Red; exit 1 }
Write-Host "      OK - dist/ erstellt"
Pop-Location

# ── Schritt 3: PyInstaller - Backend Binary erstellen ────────
Write-Host ""
Write-Host "[3/6] Backend Binary erstellen (PyInstaller)..."
Push-Location $BACKEND_DIR

# Altes Build-Verzeichnis aufraeumen
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }

pyinstaller cernis_windows.spec --noconfirm
if ($LASTEXITCODE -ne 0) { Write-Host "FEHLER: PyInstaller fehlgeschlagen" -ForegroundColor Red; exit 1 }

$BACKEND_BIN = Join-Path $BACKEND_DIR "dist\cernis-backend.exe"
if (-not (Test-Path $BACKEND_BIN)) {
    Write-Host "FEHLER: cernis-backend.exe nicht gefunden!" -ForegroundColor Red
    exit 1
}
Write-Host "      OK - $BACKEND_BIN"
Pop-Location

# ── Schritt 4: Binary fuer Tauri-Bundler bereitstellen ──────
Write-Host ""
Write-Host "[4/6] Backend Binary fuer Tauri bereitstellen..."

# Tauri externalBin erwartet: cernis-backend-x86_64-pc-windows-msvc.exe
$TAURI_BIN_NAME = "cernis-backend-x86_64-pc-windows-msvc.exe"
Copy-Item $BACKEND_BIN (Join-Path $TAURI_SRC $TAURI_BIN_NAME) -Force

# Auch in target/x86_64-pc-windows-msvc/release/ ablegen
$TAURI_RELEASE = Join-Path $TAURI_SRC "target\x86_64-pc-windows-msvc\release"
New-Item -ItemType Directory -Path $TAURI_RELEASE -Force | Out-Null
Copy-Item $BACKEND_BIN (Join-Path $TAURI_RELEASE "cernis-backend.exe") -Force

Write-Host "      OK"

# ── Schritt 5: Tauri bauen ───────────────────────────────────
Write-Host ""
Write-Host "[5/6] Tauri Build (NSIS Installer)..."
Push-Location $TAURI_DIR
npm install --silent
if ($LASTEXITCODE -ne 0) { Write-Host "FEHLER: npm install fehlgeschlagen" -ForegroundColor Red; exit 1 }
npm run build-tauri
if ($LASTEXITCODE -ne 0) { Write-Host "FEHLER: Tauri Build fehlgeschlagen" -ForegroundColor Red; exit 1 }
Pop-Location

# ── Schritt 6: Installer kopieren ────────────────────────────
Write-Host ""
Write-Host "[6/6] Installer kopieren..."

$VERSION = (Get-Content (Join-Path $TAURI_SRC "tauri.conf.json") | ConvertFrom-Json).version
$DEST = "C:\Users\Claude"

$NSIS_DIR = Join-Path $TAURI_SRC "target\x86_64-pc-windows-msvc\release\bundle\nsis"
$INSTALLER = Get-ChildItem -Path $NSIS_DIR -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($INSTALLER) {
    $DEST_FILE = Join-Path $DEST "cernis-pro_${VERSION}_x64-setup.exe"
    Copy-Item $INSTALLER.FullName $DEST_FILE -Force
    Write-Host "      -> $DEST_FILE"
} else {
    Write-Host "WARNUNG: Kein NSIS Installer gefunden in $NSIS_DIR" -ForegroundColor Yellow
    # Fallback: suche rekursiv
    $FALLBACK = Get-ChildItem -Path (Join-Path $TAURI_SRC "target") -Filter "*setup*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($FALLBACK) {
        $DEST_FILE = Join-Path $DEST "cernis-pro_${VERSION}_x64-setup.exe"
        Copy-Item $FALLBACK.FullName $DEST_FILE -Force
        Write-Host "      -> $DEST_FILE (Fallback-Pfad)"
    } else {
        Write-Host "FEHLER: Kein Installer gefunden!" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "============================================"
Write-Host " BUILD ERFOLGREICH"
Write-Host "============================================"
Write-Host ""
if ($DEST_FILE) {
    Write-Host "Installer: $DEST_FILE"
}
Write-Host ""
