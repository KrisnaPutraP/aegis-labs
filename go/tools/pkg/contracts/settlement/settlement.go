//go:generate go run github.com/ethereum/go-ethereum/cmd/abigen --abi=PolicySettlement.abi --bin=PolicySettlement.bin --pkg=settlement --type=PolicySettlement --out=autogen_policysettlement.go
//go:generate go run github.com/ethereum/go-ethereum/cmd/abigen --abi=FxrpPayoutExecutor.abi --bin=FxrpPayoutExecutor.bin --pkg=settlement --type=FxrpPayoutExecutor --out=autogen_fxrppayoutexecutor.go

// Package settlement holds the generated bindings for the Phase 4 payout
// contracts: PolicySettlement, which verifies a TEE-signed decision, and
// FxrpPayoutExecutor, the FXRP implementation of IPayoutExecutor it pays
// through. Both are produced by scripts/generate-bindings.sh and are not
// checked in.
package settlement
