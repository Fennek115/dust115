#!/usr/bin/env bash
# Publica la copia del tema de este sitio (themes/vulpine-marrow) en su repo
# standalone (Fennek115/vulpine-marrow), por espejo (rsync), no por git subtree.
#
# El sitio es la FUENTE DE VERDAD: editás el tema en themes/vulpine-marrow/ y la
# build de GitHub Pages usa esa copia vendorizada. El repo del tema es solo una
# COPIA DE DISTRIBUCIÓN publicada aparte; se actualiza a mano cuando querés sacar
# un release.
#
#   scripts/sync-theme.sh push ["mensaje de commit"]   # sitio -> repo del tema (publicar)
#   scripts/sync-theme.sh pull                          # repo del tema -> sitio (traer)
#
# 'push' refleja themes/vulpine-marrow/ sobre un clon local del repo del tema,
# commitea (te pedirá la passphrase PGP si firmás commits) y pushea por SSH.
# 'pull' hace lo inverso (raro: solo si alguien editó el repo del tema directo);
# después revisás y commiteás vos en el repo del SITIO.
#
# El clon local del repo del tema (por defecto ~/projects/vulpine-marrow) se puede
# cambiar con la variable de entorno VM_THEME_CLONE.
set -euo pipefail

PREFIX="themes/vulpine-marrow"
CLONE="${VM_THEME_CLONE:-$HOME/projects/vulpine-marrow}"
URL="git@github.com:Fennek115/vulpine-marrow.git"

ROOT="$(git rev-parse --show-toplevel)"
SRC="$ROOT/$PREFIX"

[ -d "$SRC" ] || { echo "error: no existe $SRC"; exit 1; }
if [ ! -d "$CLONE/.git" ]; then
  echo "error: no encuentro el clon del repo del tema en: $CLONE"
  echo "cloná primero:  git clone $URL \"$CLONE\""
  echo "o apuntá a otra ruta:  VM_THEME_CLONE=/ruta $0 $*"
  exit 1
fi

case "${1:-}" in
  push)
    rsync -a --delete --exclude='.git/' "$SRC/" "$CLONE/"
    cd "$CLONE"
    git add -A
    if git diff --cached --quiet; then
      echo "nada que publicar: el repo del tema ya está al día."
      exit 0
    fi
    git status --short
    git commit -m "${2:-sync: actualizar tema desde el sitio}"
    git push
    echo "✓ publicado en $URL"
    ;;
  pull)
    rsync -a --delete --exclude='.git/' "$CLONE/" "$SRC/"
    echo "✓ traído al sitio en $PREFIX/. Revisá 'git status' y commiteá vos en el repo del sitio."
    ;;
  *)
    echo "uso: $0 {push [\"mensaje\"] | pull}"; exit 1 ;;
esac
