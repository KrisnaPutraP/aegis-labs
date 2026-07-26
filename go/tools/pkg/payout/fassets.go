package payout

import (
	"context"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
)

// FlareContractRegistryAddress is the entry point to every Flare system
// contract. It is deliberately identical on Flare, Songbird, Coston and
// Coston2, which is what makes resolving FXRP by name safe to hardcode: the
// address is fixed, the thing it points at is not.
//
// Override with FLARE_CONTRACT_REGISTRY when pointing at a fork or a local
// deployment.
const FlareContractRegistryAddress = "0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019"

// AssetManagerFXRPName is the registry key for the FAssets asset manager that
// issues FXRP. On Coston2 it manages the test instance, whose token reports
// symbol FTestXRP while still being named FXRP.
const AssetManagerFXRPName = "AssetManagerFXRP"

const contractRegistryABI = `[{"inputs":[{"internalType":"string","name":"_name","type":"string"}],` +
	`"name":"getContractAddressByName","outputs":[{"internalType":"address","name":"","type":"address"}],` +
	`"stateMutability":"view","type":"function"}]`

const assetManagerABI = `[{"inputs":[],"name":"fAsset",` +
	`"outputs":[{"internalType":"address","name":"","type":"address"}],` +
	`"stateMutability":"view","type":"function"}]`

// erc20ABI is the slice of ERC-20 the payout path reads. Hand-written rather
// than generated for the same reason IERC20.sol is: three view methods do not
// justify carrying another set of bindings.
const erc20ABI = `[
	{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf",
	 "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
	{"inputs":[],"name":"symbol",
	 "outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},
	{"inputs":[],"name":"decimals",
	 "outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},
	{"inputs":[{"internalType":"address","name":"to","type":"address"},
	           {"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer",
	 "outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
]`

// ResolveFxrp finds the FXRP token address for the connected chain.
//
// Resolved through the registry rather than configured, so the same tooling
// works on Coston2 and Flare without an address list that can go stale — and so
// a wrong network fails with "no AssetManagerFXRP" instead of silently paying
// out in some other chain's token.
func ResolveFxrp(ctx context.Context, client *ethclient.Client) (common.Address, error) {
	registryAddress := common.HexToAddress(FlareContractRegistryAddress)
	if override := os.Getenv("FLARE_CONTRACT_REGISTRY"); override != "" {
		registryAddress = common.HexToAddress(override)
	}

	registryABI, err := abi.JSON(strings.NewReader(contractRegistryABI))
	if err != nil {
		return common.Address{}, errors.Errorf("parsing contract registry ABI: %s", err)
	}
	registry := bind.NewBoundContract(registryAddress, registryABI, client, nil, nil)

	opts := &bind.CallOpts{Context: ctx}

	var out []any
	if err := registry.Call(opts, &out, "getContractAddressByName", AssetManagerFXRPName); err != nil {
		return common.Address{}, errors.Errorf("resolving %s: %s", AssetManagerFXRPName, err)
	}
	assetManager, ok := out[0].(common.Address)
	if !ok || assetManager == (common.Address{}) {
		return common.Address{}, errors.Errorf(
			"%s is not registered on this chain — is the RPC pointing at a Flare network with FAssets?",
			AssetManagerFXRPName)
	}

	managerABI, err := abi.JSON(strings.NewReader(assetManagerABI))
	if err != nil {
		return common.Address{}, errors.Errorf("parsing asset manager ABI: %s", err)
	}

	out = nil
	manager := bind.NewBoundContract(assetManager, managerABI, client, nil, nil)
	if err := manager.Call(opts, &out, "fAsset"); err != nil {
		return common.Address{}, errors.Errorf("reading fAsset from %s: %s", assetManager.Hex(), err)
	}
	fAsset, ok := out[0].(common.Address)
	if !ok || fAsset == (common.Address{}) {
		return common.Address{}, errors.New("asset manager reports no fAsset")
	}

	return fAsset, nil
}

// ERC20 is a read/transfer view of one token.
type ERC20 struct {
	Address  common.Address
	contract *bind.BoundContract
}

// NewERC20 binds a token for balance reads and transfers.
func NewERC20(address common.Address, backend bind.ContractBackend) (*ERC20, error) {
	parsed, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, errors.Errorf("parsing ERC-20 ABI: %s", err)
	}

	return &ERC20{
		Address:  address,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend),
	}, nil
}

// BalanceOf reads an account's token balance, in the token's smallest unit.
func (t *ERC20) BalanceOf(ctx context.Context, account common.Address) (*big.Int, error) {
	var out []any
	if err := t.contract.Call(&bind.CallOpts{Context: ctx}, &out, "balanceOf", account); err != nil {
		return nil, errors.Errorf("balanceOf(%s): %s", account.Hex(), err)
	}

	balance, ok := out[0].(*big.Int)
	if !ok {
		return nil, errors.Errorf("balanceOf returned %T, want uint256", out[0])
	}

	return balance, nil
}

// Metadata reads the token's symbol and decimals, for logs and sanity checks.
func (t *ERC20) Metadata(ctx context.Context) (string, uint8, error) {
	opts := &bind.CallOpts{Context: ctx}

	var out []any
	if err := t.contract.Call(opts, &out, "symbol"); err != nil {
		return "", 0, errors.Errorf("symbol(): %s", err)
	}
	symbol, ok := out[0].(string)
	if !ok {
		return "", 0, errors.Errorf("symbol returned %T, want string", out[0])
	}

	out = nil
	if err := t.contract.Call(opts, &out, "decimals"); err != nil {
		return "", 0, errors.Errorf("decimals(): %s", err)
	}
	decimals, ok := out[0].(uint8)
	if !ok {
		return "", 0, errors.Errorf("decimals returned %T, want uint8", out[0])
	}

	return symbol, decimals, nil
}

// Transfer moves tokens from the signer to `to`.
func (t *ERC20) Transfer(opts *bind.TransactOpts, to common.Address, amount *big.Int) (common.Hash, error) {
	tx, err := t.contract.Transact(opts, "transfer", to, amount)
	if err != nil {
		return common.Hash{}, errors.Errorf("transfer: %s", err)
	}

	return tx.Hash(), nil
}

// FormatUnits renders an integer amount as a decimal string with `decimals`
// places, for logs only. Nothing downstream parses it back.
func FormatUnits(amount *big.Int, decimals uint8) string {
	if amount == nil {
		return "<nil>"
	}

	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	quotient, remainder := new(big.Int).QuoRem(amount, scale, new(big.Int))

	if remainder.Sign() == 0 {
		return quotient.String()
	}

	fraction := strings.TrimRight(leftPad(remainder.String(), int(decimals)), "0")

	return quotient.String() + "." + fraction
}

func leftPad(s string, width int) string {
	if len(s) >= width {
		return s
	}

	return strings.Repeat("0", width-len(s)) + s
}
