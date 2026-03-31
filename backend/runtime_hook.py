"""PyInstaller runtime hook for CERNIS PRO backend."""
import sys
import os

if hasattr(sys, '_MEIPASS'):
    # Add bundle dir to path
    sys.path.insert(0, sys._MEIPASS)
    sys.path.insert(0, os.path.join(sys._MEIPASS, 'modules'))
    
    # Mark as frozen for uvicorn
    sys.frozen = True
    
    # Fix multiprocessing
    import multiprocessing
    multiprocessing.freeze_support()
