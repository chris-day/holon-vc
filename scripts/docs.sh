#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -x .venv/bin/zensical ]]; then
  printf '%s\n' 'Install documentation dependencies: .venv/bin/python -m pip install -r requirements-docs.txt' >&2
  exit 1
fi
case "${1:-build}" in
  build) exec .venv/bin/zensical build --clean --strict ;;
  serve) exec .venv/bin/zensical serve ;;
  *) printf '%s\n' 'Usage: bash scripts/docs.sh [build|serve]' >&2; exit 2 ;;
esac
