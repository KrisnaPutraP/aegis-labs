#!/usr/bin/env bash
#
# Start or stop the read-only bridge to the extension proxy's signed action
# results.
#
# Settling from the browser needs GET /action/result/<instructionId>, and the
# proxy sets no CORS header, so the response is unreadable cross-origin. Reaching
# it through the public ngrok tunnel does not help either: that tunnel serves a
# browser an HTML interstitial, and the header that skips it forces a preflight
# the tunnel answers with 405.
#
# This script builds cmd/result-bridge, runs it as a container joined to the
# stack's own network so the tunnel is out of the picture entirely, and publishes
# it on loopback only. The bridge serves one route and one method and refuses
# everything else, so POST /action stays out of reach.
#
# Usage:
#   ./scripts/result-bridge.sh start     # build and run, then check the endpoint
#   ./scripts/result-bridge.sh stop
#   ./scripts/result-bridge.sh status
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[result-bridge]${NC} $*"; }
die() { echo -e "${RED}[result-bridge] ERROR:${NC} $*" >&2; exit 1; }

CONTAINER=aegis-result-bridge
HOST_PORT=7704
RUNTIME_IMAGE=alpine:3
BIN_DIR="$PROJECT_DIR/go/tools/bin"
BIN="$BIN_DIR/result-bridge"

ACTION="${1:-start}"

case "$ACTION" in
    stop)
        docker rm -f "$CONTAINER" >/dev/null 2>&1 && log "stopped" || log "not running"
        exit 0
        ;;
    status)
        if docker ps --filter "name=^/${CONTAINER}$" --format '{{.Names}}' | grep -q .; then
            log "running on http://127.0.0.1:${HOST_PORT}"
            # No instruction id is assumed here. A bad id is the cheapest way to
            # prove the route is alive without inventing one that might exist.
            code="$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
                "http://127.0.0.1:${HOST_PORT}/action/result/not-an-id" || true)"
            log "GET /action/result/not-an-id returned ${code} (400 means the route is up and validating)"
        else
            log "not running"
        fi
        exit 0
        ;;
    start) ;;
    *) die "unknown action: $ACTION (use start, stop or status)" ;;
esac

# The proxy container carries the compose service label, so the network name is
# read from the running stack rather than assumed.
PROXY_CONTAINER="$(docker ps --filter label=com.docker.compose.service=ext-proxy --format '{{.Names}}' | head -1)"
[[ -n "$PROXY_CONTAINER" ]] || die "ext-proxy container is not running. Start the stack first: ./scripts/start-services.sh"

NETWORK="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$PROXY_CONTAINER")"
[[ -n "$NETWORK" ]] || die "could not determine the Docker network of $PROXY_CONTAINER"
log "proxy container: $PROXY_CONTAINER on network $NETWORK"

log "building the bridge"
mkdir -p "$BIN_DIR"
(cd "$PROJECT_DIR/go/tools" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/result-bridge)

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# Published on 127.0.0.1 only: this is a demo aid for the operator's browser, not
# something to expose on a network.
docker run --rm -d \
    --name "$CONTAINER" \
    --network "$NETWORK" \
    -p "127.0.0.1:${HOST_PORT}:7704" \
    -v "$BIN:/usr/local/bin/result-bridge:ro" \
    --entrypoint /usr/local/bin/result-bridge \
    "$RUNTIME_IMAGE" \
    -listen :7704 -upstream "http://ext-proxy:6664" >/dev/null

sleep 1
log "bridge is up on http://127.0.0.1:${HOST_PORT}/action/result/<instructionId>"
code="$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    "http://127.0.0.1:${HOST_PORT}/action/result/not-an-id" || true)"
[[ "$code" == "400" ]] || die "the bridge answered ${code} for a malformed id, expected 400"
log "route is up and validating ids"
log "stop it with: ./scripts/result-bridge.sh stop"
