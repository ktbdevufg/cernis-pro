#!/bin/bash
# ============================================================
#  CERNIS PRO - Build in Docker (reproduzierbare Werkbank)
#  Baut das Build-Image aus Dockerfile.build und fuehrt darin
#  den unveraenderten build-linux.sh gegen das als Volume
#  gemountete Repo aus. Die erzeugten deb/rpm landen im
#  gemounteten Repo unter src-tauri/target/.../bundle/ und sind
#  damit fuer den Host sichtbar.
#
#  Aufruf (bash, User):  bash build-in-docker.sh
# ============================================================
set -euo pipefail

# Repo-Root = Verzeichnis dieses Skripts (absoluter Pfad)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="cernis-build:local"
TRIPLE="x86_64-unknown-linux-gnu"

echo "============================================"
echo " CERNIS PRO - Build in Docker"
echo " Repo-Root: $REPO_ROOT"
echo " Image-Tag: $IMAGE_TAG"
echo "============================================"

# ------------------------------------------------------------
# 1) Image bauen
# ------------------------------------------------------------
echo ""
echo "[1/3] Docker-Image bauen ($IMAGE_TAG) ..."
docker build -f "$REPO_ROOT/Dockerfile.build" -t "$IMAGE_TAG" "$REPO_ROOT"

# ------------------------------------------------------------
# 2) Container starten, Repo read-write nach /build mounten,
#    Deps synchronisieren, dann den unveraenderten Build fahren.
#
#    WICHTIG: '-v /build/.venv' legt ein anonymes Docker-Volume
#    genau auf /build/.venv und ueberlagert damit die vom Host
#    gemountete .venv. Der Container bekommt an dieser Stelle eine
#    EIGENE, frische (leere) Schicht -> 'uv sync' installiert dort
#    vollstaendig neu (inkl. Dev-Gruppe/PyInstaller), OHNE die
#    Host-.venv zu veraendern. Bei '--rm' wird das anonyme Volume
#    nach dem Lauf automatisch verworfen. build-linux.sh bleibt
#    unveraendert, da .venv weiterhin unter dem Repo-Root liegt.
# ------------------------------------------------------------
echo ""
echo "[2/3] Build im Container ausfuehren ..."
docker run --rm \
    -v "$REPO_ROOT":/build \
    -v /build/.venv \
    -w /build \
    "$IMAGE_TAG" \
    bash -c '
        set -e
        echo "--- uv sync (Deps + .venv, inkl. Dev-Gruppe fuer PyInstaller) ---"
        if [ -f uv.lock ]; then
            uv sync --frozen --group dev
        else
            uv sync --all-groups
        fi
        echo "--- build-linux.sh (unveraendert) ---"
        bash build-linux.sh
    '

# ------------------------------------------------------------
# 3) Ergebnis: wo liegt die deb?
# ------------------------------------------------------------
echo ""
echo "[3/3] Ergebnis einsammeln ..."
BUNDLE_DIR="$REPO_ROOT/src-tauri/target/$TRIPLE/release/bundle"
DEB="$(find "$BUNDLE_DIR/deb" -name '*.deb' -print -quit 2>/dev/null || true)"

echo ""
echo "============================================"
echo " BUILD FERTIG"
echo "============================================"
if [ -n "$DEB" ]; then
    echo " deb:      $DEB"
else
    echo " deb:      NICHT GEFUNDEN unter $BUNDLE_DIR/deb"
fi
echo "============================================"
