#!/usr/bin/env bash
#
# Record what the enclave answers, so the hosted copy of the page has something
# honest to show where it cannot ask.
#
# The dashboard reads contract state from the public Coston2 RPC and event
# history from the public explorer, so a hosted copy keeps working with nobody
# online. One panel is different: the enclave's GET /state lives inside the
# stack's Docker network and is not published to the internet, by design. A page
# on static hosting can never call it.
#
# This writes web/enclave-snapshot.json, which the hosted page replays verbatim
# under a "last known state" label, saying plainly that it is a recording and not
# a live call. The alternative, an endpoint that fails in a visitor's browser,
# would read as a broken product rather than the boundary it actually is.
#
# What is recorded is a model count and a version string. No parameter is in it,
# and the enclave has no route that would return one, which is the point the
# panel exists to make. Delete the file to drop the panel from the hosted page
# entirely: it removes itself rather than showing a dead endpoint.
#
# Run this before deploying, whenever the enclave's state has changed in a way
# worth showing (after reregister-all, for instance).
#
# Usage:
#   ./scripts/record-enclave-state.sh
#   ./scripts/record-enclave-state.sh --state-url http://127.0.0.1:7703/state
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[record-enclave]${NC} $*"; }
die() { echo -e "${RED}[record-enclave] ERROR:${NC} $*" >&2; exit 1; }

STATE_URL="http://127.0.0.1:7703/state"
OUT="$PROJECT_DIR/web/enclave-snapshot.json"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --state-url) STATE_URL="${2:?--state-url needs a value}"; shift 2 ;;
        --out) OUT="${2:?--out needs a value}"; shift 2 ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

log "asking $STATE_URL"
body="$(curl -sS -m 10 "$STATE_URL" 2>/dev/null || true)"
status="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "$STATE_URL" 2>/dev/null || echo 000)"

if [[ "$status" != "200" || -z "$body" ]]; then
    die "the enclave state endpoint answered ${status}.
       Start the stack and the read only bridge first:
         ./scripts/start-services.sh
         ./scripts/state-bridge.sh start
       Nothing was written, so the page keeps the recording it already had."
fi

BODY="$body" STATUS="$status" ENDPOINT="$STATE_URL" python3 - "$OUT" <<'PY'
import datetime, json, os, sys

snapshot = {
    "capturedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "endpoint": os.environ["ENDPOINT"],
    "httpStatus": int(os.environ["STATUS"]),
    "body": os.environ["BODY"].strip(),
    "note": (
        "Recorded by scripts/record-enclave-state.sh. The hosted page replays this "
        "verbatim and labels it as a recording, because static hosting has no route "
        "to the enclave. A model count and a version string are all this endpoint "
        "has ever returned."
    ),
}
with open(sys.argv[1], "w") as f:
    json.dump(snapshot, f, indent=2)
    f.write("\n")
PY

log "wrote $OUT"
log "  $(echo "$body" | head -c 140)"
log ""
log "the local page still calls the enclave live. This is only what the hosted copy shows."
