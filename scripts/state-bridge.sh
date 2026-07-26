#!/usr/bin/env bash
#
# Start or stop the read-only bridge to the enclave's GET /state endpoint.
#
# The extension serves /state on port 7702 inside the stack's Docker network and
# that port is not published to the host, so the demo page cannot reach it. This
# script builds cmd/state-bridge, runs it as a container joined to that same
# network, and publishes it on loopback only. The bridge serves GET /state and
# refuses everything else, so POST /action stays out of reach.
#
# Usage:
#   ./scripts/state-bridge.sh start     # build and run, then curl the endpoint
#   ./scripts/state-bridge.sh stop
#   ./scripts/state-bridge.sh status
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[state-bridge]${NC} $*"; }
die() { echo -e "${RED}[state-bridge] ERROR:${NC} $*" >&2; exit 1; }

CONTAINER=aegis-state-bridge
HOST_PORT=7703
RUNTIME_IMAGE=alpine:3
BIN_DIR="$PROJECT_DIR/go/tools/bin"
BIN="$BIN_DIR/state-bridge"

ACTION="${1:-start}"

case "$ACTION" in
    stop)
        docker rm -f "$CONTAINER" >/dev/null 2>&1 && log "stopped" || log "not running"
        exit 0
        ;;
    status)
        if docker ps --filter "name=^/${CONTAINER}$" --format '{{.Names}}' | grep -q .; then
            log "running, checking the endpoint"
            curl -sS -m 5 "http://127.0.0.1:${HOST_PORT}/state" && echo
        else
            log "not running"
        fi
        exit 0
        ;;
    start) ;;
    *) die "unknown action: $ACTION (use start, stop or status)" ;;
esac

# The extension container carries the compose service label, so the network name
# is read from the running stack rather than assumed.
EXT_CONTAINER="$(docker ps --filter label=com.docker.compose.service=extension-tee --format '{{.Names}}' | head -1)"
[[ -n "$EXT_CONTAINER" ]] || die "extension-tee container is not running. Start the stack first: ./scripts/start-services.sh"

NETWORK="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$EXT_CONTAINER")"
[[ -n "$NETWORK" ]] || die "could not determine the Docker network of $EXT_CONTAINER"
log "extension container: $EXT_CONTAINER on network $NETWORK"

log "building the bridge"
mkdir -p "$BIN_DIR"
(cd "$PROJECT_DIR/go/tools" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/state-bridge)

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# Published on 127.0.0.1 only: this is a demo aid for the operator's browser,
# not something to expose on a network.
docker run --rm -d \
    --name "$CONTAINER" \
    --network "$NETWORK" \
    -p "127.0.0.1:${HOST_PORT}:7703" \
    -v "$BIN:/usr/local/bin/state-bridge:ro" \
    --entrypoint /usr/local/bin/state-bridge \
    "$RUNTIME_IMAGE" \
    -listen :7703 -upstream "http://extension-tee:7702/state" >/dev/null

sleep 1
log "bridge is up on http://127.0.0.1:${HOST_PORT}/state"
curl -sS -m 5 "http://127.0.0.1:${HOST_PORT}/state" && echo
log "stop it with: ./scripts/state-bridge.sh stop"
