#!/usr/bin/env bash
#
# Serve the web demo in web/.
#
# The page is plain HTML, CSS and JavaScript with no build step and no
# dependencies, so any static server works. This one also starts the two
# read-only bridges when the stack is running, because two panels reach past the
# chain: the sealed model panel reads GET /state, and settling from the browser
# reads the enclave's signed result.
#
# The dashboard reads Coston2 and needs no wallet. The "Try it yourself" section
# is the only part that sends a transaction, and it signs through the visitor's
# own wallet. Nothing here ever handles a private key.
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

# Settling from the browser needs the enclave's signed result, and the extension
# proxy serves it without a CORS header. Evaluation works without this bridge;
# only the settle step reports the result as unreachable.
if docker ps --filter label=com.docker.compose.service=ext-proxy --format '{{.Names}}' | grep -q .; then
    log "starting the read-only action result bridge"
    "$SCRIPT_DIR/result-bridge.sh" start
else
    warn "the extension proxy is not running, so settling from the browser has no route to the signed result."
fi

log "serving $PROJECT_DIR/web on http://127.0.0.1:${PORT}"
log "stop with Ctrl-C, then ./scripts/state-bridge.sh stop and ./scripts/result-bridge.sh stop"
cd "$PROJECT_DIR/web"
exec python3 -m http.server "$PORT" --bind 127.0.0.1
