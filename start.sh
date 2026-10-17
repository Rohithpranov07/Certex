#!/usr/bin/env bash
# CERTEX launcher.
#   ./start.sh            set up the venv if needed, then serve the web demo page
#   ./start.sh web [PORT] same as above (default port 8765)
#   ./start.sh demo       run the five-step terminal demo (demo/demo.sh)
#   ./start.sh all        run the terminal demo, then serve the web demo page
#   ./start.sh setup      only create the venv and install the package
#   ./start.sh test       run the fast pytest suite
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
VENV=".venv"

setup() {
  if [ ! -x "$VENV/bin/certex" ]; then
    echo ">> Setting up $VENV and installing certex (editable, dev extras)"
    [ -d "$VENV" ] || "$PY" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -e ".[dev]"
  fi
  # shellcheck disable=SC1091
  . "$VENV/bin/activate"
}

web() {
  local port="${1:-8765}"
  echo ">> Web demo on http://127.0.0.1:$port  (Ctrl-C to stop)"
  python demo/server.py --port "$port"
}

case "${1:-web}" in
  setup) setup ;;
  web)   setup; web "${2:-8765}" ;;
  demo)  setup; bash demo/demo.sh ;;
  all)   setup; bash demo/demo.sh; echo; web "${2:-8765}" ;;
  test)  setup; pytest -q ;;
  -h|--help|help) sed -n '2,8p' "$0" ;;
  *) echo "Unknown command: $1 (try ./start.sh help)" >&2; exit 2 ;;
esac
