#!/usr/bin/env bash
# generate-bindings.sh — Compile Solidity contracts and generate Go bindings.
#
# Prerequisites: forge (Foundry), jq
#
# Usage: ./scripts/generate-bindings.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Contracts to bind: "<ContractName>:<SourceFile>:<GoPackage>" ---
#
# One Go package may hold several contracts; abigen writes one file per contract
# (autogen_<lowercased name>.go), so the package directory needs one
# //go:generate line per entry here. See pkg/contracts/*/doc file.
CONTRACTS=(
    "InstructionSender:InstructionSender.sol:sign"
    "PolicySettlement:PolicySettlement.sol:settlement"
    "FxrpPayoutExecutor:FxrpPayoutExecutor.sol:settlement"
)

cd "$PROJECT_DIR"

echo "=== Step 1: Compile Solidity contracts ==="
forge build

echo "=== Step 2: Extract ABI and BIN ==="
declare -A SEEN_PACKAGES=()

for entry in "${CONTRACTS[@]}"; do
    IFS=':' read -r CONTRACT_NAME SOURCE_FILE GO_PKG <<< "$entry"
    BINDINGS_DIR="$PROJECT_DIR/go/tools/pkg/contracts/$GO_PKG"

    # Verify the contract name in the source matches what we expect
    if ! grep -q "contract ${CONTRACT_NAME}" "$PROJECT_DIR/contracts/${SOURCE_FILE}" 2>/dev/null; then
        echo ""
        echo "ERROR: Contract name '${CONTRACT_NAME}' not found in contracts/${SOURCE_FILE}."
        echo "Make sure the contract name in the source matches this script's CONTRACTS list."
        exit 1
    fi

    FORGE_OUT="$PROJECT_DIR/out/${SOURCE_FILE}/${CONTRACT_NAME}.json"
    if [[ ! -f "$FORGE_OUT" ]]; then
        echo "ERROR: forge output not found at $FORGE_OUT"
        echo "Check that the contract name matches your Solidity contract name."
        exit 1
    fi

    mkdir -p "$BINDINGS_DIR"

    # Extract ABI (JSON array)
    jq '.abi' "$FORGE_OUT" > "$BINDINGS_DIR/${CONTRACT_NAME}.abi"

    # Extract bytecode (hex string, strip 0x prefix)
    jq -r '.bytecode.object' "$FORGE_OUT" | sed 's/^0x//' > "$BINDINGS_DIR/${CONTRACT_NAME}.bin"

    echo "  ABI → $BINDINGS_DIR/${CONTRACT_NAME}.abi"
    echo "  BIN → $BINDINGS_DIR/${CONTRACT_NAME}.bin"

    SEEN_PACKAGES["$GO_PKG"]=1
done

echo "=== Step 3: Generate Go bindings ==="
cd "$PROJECT_DIR/go/tools"
for GO_PKG in "${!SEEN_PACKAGES[@]}"; do
    go generate "./pkg/contracts/$GO_PKG/"
    echo "  Generated bindings in pkg/contracts/$GO_PKG"
done

echo "=== Done ==="
