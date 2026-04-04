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
datas += [('modules', 'modules')]
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
    ['main.py'],
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
