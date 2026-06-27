#!/bin/bash
# ============================================================
#  CERNIS PRO – Dev-Helfer: CAP_NET_RAW fuer den Sniff-Helfer
# ============================================================
# Im Dev laeuft der Sniff-Helfer als  python backend/sniffd.py  -- eine
# Capability kann NICHT auf eine .py-Datei gesetzt werden. Deshalb traegt
# im Dev der venv-python-Interpreter die Cap (er startet den Helfer).
# In Produktion traegt das frozen Binary cernis-sniffd die Cap (Postinstall).
#
# Aufruf bewusst durch Karl:  bash scripts/dev-setcap-sniffd.sh
# Das Skript fuehrt sudo NICHT verdeckt aus -- es zeigt den exakten
# setcap-Befehl und ruft ihn dann auf.
# ============================================================
set -euo pipefail

# Repo-Root robust ermitteln (Skript liegt in scripts/, Root ist dessen Parent).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# venv-python ueber uv ermitteln (der Interpreter, der den Helfer startet).
VENV_PYTHON="$(cd "${REPO_ROOT}" && uv run python -c "import sys; print(sys.executable)")"

# venv-python ist oft ein Symlink -- setcap muss auf die echte Datei.
REAL_PYTHON="$(realpath "${VENV_PYTHON}")"

echo "Repo-Root:    ${REPO_ROOT}"
echo "venv-python:  ${VENV_PYTHON}"
echo "real python:  ${REAL_PYTHON}"
echo ""
echo "Hinweis: setcap braucht root-Rechte. Es wird jetzt ausgefuehrt:"
echo "  sudo setcap cap_net_raw+eip ${REAL_PYTHON}"
echo ""

sudo setcap cap_net_raw+eip "${REAL_PYTHON}"  #
