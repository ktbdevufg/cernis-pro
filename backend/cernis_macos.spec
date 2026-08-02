# -*- mode: python ; coding: utf-8 -*-
# ============================================================
#  CERNIS PRO – macOS PyInstaller Spec
#  Build arm64:  pyinstaller cernis_macos.spec
# ============================================================
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None
datas = []
hiddenimports = []
binaries = []

# ── Core frameworks ───────────────────────────────────────────
for pkg in ['fastapi', 'starlette', 'uvicorn', 'anyio', 'h11',
            'httptools', 'websockets', 'watchfiles', 'click']:
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

# ── Cryptography ──────────────────────────────────────────────
d, b, h = collect_all('cryptography')
datas += d; binaries += b; hiddenimports += h

# ── Scheduler ─────────────────────────────────────────────────
d, b, h = collect_all('apscheduler')
datas += d; binaries += b; hiddenimports += h

# ── DNS / mDNS ────────────────────────────────────────────────
for pkg in ['dns', 'zeroconf', 'ifaddr']:
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

# ── FritzBox ──────────────────────────────────────────────────
d, b, h = collect_all('fritzconnection')
datas += d; binaries += b; hiddenimports += h

# ── SNMP ──────────────────────────────────────────────────────
d, b, h = collect_all('pysnmp')
datas += d; binaries += b; hiddenimports += h

# ── PDF Export ────────────────────────────────────────────────
d, b, h = collect_all('reportlab')
# Schriftverzeichnis von reportlab verwerfen: das Produkt setzt ausschliesslich die
# PDF-Standardschriften (Helvetica, Helvetica-Bold, Helvetica-Oblique), die keine
# Schriftdatei brauchen. Es gibt im Backend keine Schriftregistrierung, die mit-
# gelieferten Dateien sind reiner Beifang von collect_all. Beide Pfadtrenner pruefen,
# weil dieselbe Konstruktion unter Windows gebaut wird. reportlab selbst bleibt voll-
# staendig erhalten -- gefiltert wird nur das Zielverzeichnis 'reportlab/fonts'.
d = [
    (_quelle, _ziel)
    for _quelle, _ziel in d
    if _ziel.replace('\\', '/').rstrip('/') != 'reportlab/fonts'
    and not _ziel.replace('\\', '/').startswith('reportlab/fonts/')
]
datas += d; binaries += b; hiddenimports += h

# ── Scapy (optional – needs libpcap at runtime, not at build) ─
try:
    d, b, h = collect_all('scapy')
    datas += d; binaries += b; hiddenimports += h
except Exception:
    pass

# ── psutil ────────────────────────────────────────────────────
d, b, h = collect_all('psutil')
datas += d; binaries += b; hiddenimports += h

# ── Application files ─────────────────────────────────────────
# modules/ nur als Quelltext bundlen -- kein __pycache__/.pyc (ADR-0004 P.4c).
# Pauschales ('modules','modules') wuerde verwaiste .pyc geloeschter Altcode-modules
# (P.4) mitnehmen; das .py-glob fasst nur die lebenden Quelldateien.
datas += [
    (str(p), 'modules')
    for p in __import__('pathlib').Path('modules').glob('*.py')
]
if os.path.exists('data'):
    datas += [('data', 'data')]
if os.path.exists('data/oui.json'):
    datas += [('data/oui.json', 'data')]

# ── macOS: include frontend-dist INSIDE the bundle (_MEIPASS) ─
frontend_dist = os.path.join('..', 'frontend', 'dist')
if os.path.exists(frontend_dist):
    datas += [(frontend_dist, 'frontend-dist')]
else:
    print(f"WARNING: frontend dist not found at {os.path.abspath(frontend_dist)}")

# ── Handbuch-Inhalte: help_content.json liegt nur in frontend/src/lib (NICHT in
# frontend/dist), darum eigens als Datenfile unter _MEIPASS/help/ mitgeben. app.py loest
# den Pfad im Frozen-Build auf _MEIPASS/help/help_content.json auf (resolve_bundle_path).
help_content = os.path.join('..', 'frontend', 'src', 'lib', 'help_content.json')
if os.path.exists(help_content):
    datas += [(help_content, 'help')]
else:
    print(f"WARNING: help_content.json not found at {os.path.abspath(help_content)}")

# ── Hidden imports ────────────────────────────────────────────
hiddenimports += [
    'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto',
    'uvicorn.loops.asyncio', 'uvicorn.protocols',
    'uvicorn.protocols.http', 'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.websockets_impl',
    'uvicorn.lifespan', 'uvicorn.lifespan.on',
    'fastapi.middleware.cors',
    'fastapi.staticfiles',
    'fastapi.responses',
    'starlette.routing',
    'starlette.middleware.cors',
    'email.mime.text',
    'email.mime.multipart',
    'sqlite3',
    'xml.etree.ElementTree',
    '_cffi_backend',
    'multiprocessing',
    'concurrent.futures',
]

# ── Analysis ──────────────────────────────────────────────────
a = Analysis(
    ['serve.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['runtime_hook.py'],
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'PyQt5', 'PySide2', 'wx', 'gi', 'cv2',
        'torch', 'tensorflow',
        # Windows-only
        'winreg',
        'ctypes.wintypes',
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cernis-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
)
