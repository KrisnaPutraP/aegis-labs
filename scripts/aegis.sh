#!/usr/bin/env bash
#
# Wrapper for the Aegis demo command line, so a demo types "aegis evaluate"
# rather than a go run invocation.
#
# It builds cmd/aegis once into go/tools/bin and runs it, rebuilding only when a
# source file is newer than the binary. The command finds the project root and
# reads .env, config/extension.env and config/settlement.env itself, so it works
# from any directory.
#
# Usage:
#   ./scripts/aegis.sh <command> [flags]
#   alias aegis="$PWD/scripts/aegis.sh"     # then: aegis evaluate --policy drought-surabaya
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN="$PROJECT_DIR/go/tools/bin/aegis"
SRC_DIR="$PROJECT_DIR/go/tools/cmd/aegis"

needs_build=false
if [[ ! -x "$BIN" ]]; then
    needs_build=true
else
    while IFS= read -r source_file; do
        [[ "$source_file" -nt "$BIN" ]] && needs_build=true && break
    done < <(find "$SRC_DIR" -name '*.go')
fi

if [[ "$needs_build" == true ]]; then
    mkdir -p "$(dirname "$BIN")"
    (cd "$PROJECT_DIR/go/tools" && go build -o "$BIN" ./cmd/aegis)
fi

exec "$BIN" "$@"
