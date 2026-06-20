#!/usr/bin/env bash
# Sincroniza la copia del tema en este sitio (themes/vulpine-marrow) con su repo
# standalone, usando git subtree. El sitio conserva su copia vendorizada (la build
# de GitHub Pages la necesita), pero podés publicar/traer cambios con un comando.
#
#   scripts/sync-theme.sh push   # sitio  -> repo del tema (publicar cambios)
#   scripts/sync-theme.sh pull   # repo del tema -> sitio (traer cambios)
#
# Antes de 'push' commiteá tus cambios del tema en el sitio (subtree push parte de
# los commits ya hechos). El primer 'push' siembra el repo del tema (debe existir
# vacío en GitHub).
set -euo pipefail

PREFIX="themes/vulpine-marrow"
REMOTE="vm-theme"
URL="git@github.com:Fennek115/vulpine-marrow.git"
BRANCH="main"

cd "$(git rev-parse --show-toplevel)"
git remote get-url "$REMOTE" >/dev/null 2>&1 || git remote add "$REMOTE" "$URL"

case "${1:-}" in
  push) git subtree push --prefix="$PREFIX" "$REMOTE" "$BRANCH" ;;
  pull) git subtree pull --prefix="$PREFIX" "$REMOTE" "$BRANCH" --squash ;;
  *)    echo "uso: $0 {push|pull}"; exit 1 ;;
esac
