# -*- mode: python ; coding: utf-8 -*-
# ============================================================
#  CERNIS PRO – Sniff-Helfer (cernis-sniffd) Linux PyInstaller Spec
#  Build x64:   pyinstaller cernis_sniffd_linux.spec
#  Schlanker Helfer: KEIN fastapi/uvicorn/starlette/reportlab/pysnmp/
#  fritzconnection/apscheduler/zeroconf/dns/keyring/pydantic.
#  Privilege-Separation Etappe 5 (S5-Lehre): die CAP_NET_RAW-Cap sitzt
#  auf diesem Helfer, nicht auf dem Backend.
# ============================================================
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None
datas = []
hiddenimports = []
binaries = []

# ── Scapy (optional – needs libpcap at runtime, not at build) ─
try:
    d, b, h = collect_all('scapy')
    datas += d; binaries += b; hiddenimports += h
except Exception:
    pass

# ── psutil ────────────────────────────────────────────────────
d, b, h = collect_all('psutil')
datas += d; binaries += b; hiddenimports += h

# ── structlog ─────────────────────────────────────────────────
d, b, h = collect_all('structlog')
datas += d; binaries += b; hiddenimports += h

# ── Hidden imports ────────────────────────────────────────────
# Nur was der Helfer zieht: kein uvicorn/fastapi/starlette/email.mime/
# xml.etree/sqlite3. scapy-contrib (LLDP/CDP) explizit ergaenzen.
hiddenimports += [
    '_cffi_backend',
    'multiprocessing',
    'concurrent.futures',
    'scapy.contrib.lldp',
    'scapy.contrib.cdp',
]

# ── Analysis ──────────────────────────────────────────────────
a = Analysis(
    ['sniffd.py'],
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
        # macOS-only
        'objc', 'AppKit', 'Foundation',
        # harte Garantie: Backend-only Deps duerfen NICHT mitkommen
        'fastapi', 'uvicorn', 'starlette', 'reportlab',
        'pysnmp', 'fritzconnection', 'keyring',
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
    name='cernis-sniffd',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
