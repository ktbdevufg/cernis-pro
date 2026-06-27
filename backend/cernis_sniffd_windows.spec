# -*- mode: python ; coding: utf-8 -*-
# ============================================================
#  CERNIS PRO – Sniff-Helfer (cernis-sniffd) Windows x64 PyInstaller Spec
#  Build:  pyinstaller cernis_sniffd_windows.spec
#  Schlanker Helfer: KEIN fastapi/uvicorn/starlette/reportlab/pysnmp/
#  fritzconnection/apscheduler/zeroconf/dns/keyring/pydantic.
# ============================================================
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None
datas = []
hiddenimports = []
binaries = []

# ── Scapy (needs Npcap at runtime on Windows) ────────────────
# collect_all('scapy') fails on Windows ("not a package" warning),
# so we collect submodules explicitly + add hiddenimports
try:
    hiddenimports += collect_submodules('scapy')
    d = collect_data_files('scapy')
    datas += d
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
# xml.etree/sqlite3. scapy explizit (collect_all faellt auf Windows aus),
# scapy-contrib (LLDP/CDP) ergaenzt.
hiddenimports += [
    '_cffi_backend',
    'multiprocessing',
    'concurrent.futures',
    # Windows-specific
    'winreg',
    'ctypes.wintypes',
    # Scapy — explicit imports (collect_all fails on Windows)
    'scapy', 'scapy.all', 'scapy.layers.all', 'scapy.layers.inet',
    'scapy.layers.inet6', 'scapy.layers.l2', 'scapy.sendrecv',
    'scapy.arch', 'scapy.arch.windows',
    'scapy.contrib.lldp', 'scapy.contrib.cdp',
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
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)
