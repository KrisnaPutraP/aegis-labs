#!/usr/bin/env bash
#
# Serve the read-only web demo in web/.
#
# The page is plain HTML, CSS and JavaScript with no build step and no
# dependencies, so any static server works. This one also starts the read-only
# enclave state bridge when the stack is running, because the sealed model panel
# reads GET /state through it.
#
# The page reads Coston2 and nothing else. It connects no wallet and sends no
# transaction.
#
# Usage:
#   ./scripts/demo-web.sh            # serve on http://127.0.0.1:5173
#   ./scripts/demo-web.sh --port 8080
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[demo-web]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo-web]${NC} $*"; }
die()  { echo -e "${RED}[demo-web] ERROR:${NC} $*" >&2; exit 1; }

PORT=5173
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) [[ $# -ge 2 ]] || die "--port requires a value"; PORT="$2"; shift 2 ;;
        --port=*) PORT="${1#--port=}"; shift ;;
        *) die "Unknown argument: $1" ;;
    esac
done

command -v python3 >/dev/null || die "python3 is needed to serve the static files"

# The dashboard reads the chain either way, so a missing bridge is a warning and
# not a failure. The sealed model panel then reports the endpoint as unreachable
# instead of showing a number nobody measured.
if docker ps --filter label=com.docker.compose.service=extension-tee --format '{{.Names}}' | grep -q .; then
    log "starting the read-only enclave state bridge"
    "$SCRIPT_DIR/state-bridge.sh" start
else
    warn "the extension stack is not running, so GET /state has no route."
    warn "the dashboard still reads Coston2, and the reveal button will report the endpoint as unreachable."
fi

log "serving $PROJECT_DIR/web on http://127.0.0.1:${PORT}"
log "stop with Ctrl-C, then ./scripts/state-bridge.sh stop"
cd "$PROJECT_DIR/web"
exec python3 -m http.server "$PORT" --bind 127.0.0.1
