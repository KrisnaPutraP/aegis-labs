// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC20 } from "./interfaces/IERC20.sol";
import { IPayoutExecutor } from "./interfaces/IPayoutExecutor.sol";

/// @title FxrpPayoutExecutor
/// @author Acex
/// @notice Settles Aegis claims in FXRP on Flare, out of a pool it holds itself.
///
/// @dev This is implementation A of ARCHITECTURE.md D4. It is deliberately the
///      dullest contract in the system: all of the judgement — whose decision to
///      believe, whether a policy may still be paid — happens in PolicySettlement
///      before this is ever called. Everything here is "move tokens, or revert".
///
///      Funding is a plain ERC-20 transfer to this address; there is no deposit
///      function to get wrong. The pool balance *is* the liquidity, which is also
///      what makes underfunding fail loudly: the transfer reverts and the policy
///      stays unsettled rather than being marked paid against money that was not
///      there.
contract FxrpPayoutExecutor is IPayoutExecutor {
    /// @notice The FAssets FXRP token this executor pays in.
    /// @dev On Coston2 this is the FAssets test instance (symbol FTestXRP, 6
    ///      decimals), resolved from the Flare contract registry at deploy time
    ///      rather than hardcoded.
    IERC20 public immutable FXRP;

    /// @notice The only contract allowed to spend the pool.
    /// @dev Immutable on purpose. The swap direction that matters is the other
    ///      one — settlement pointing at a different executor — and letting the
    ///      executor be re-pointed at a new settlement contract would mean a
    ///      compromised owner could drain the pool through a settlement contract
    ///      of their own.
    address public immutable SETTLEMENT;

    /// @notice Who may top the pool up or withdraw the remainder.
    address public immutable OWNER;

    /// @notice Emitted when the owner takes unclaimed float back out.
    event PoolWithdrawn(address indexed to, uint256 amount);

    error NotSettlement();
    error NotOwner();
    error ZeroAddress();
    error ZeroAmount();
    error InsufficientLiquidity(uint256 requested, uint256 available);
    error TransferFailed();

    modifier onlySettlement() {
        require(msg.sender == SETTLEMENT, NotSettlement());
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == OWNER, NotOwner());
        _;
    }

    /// @param _fxrp FAssets FXRP token address.
    /// @param _settlement PolicySettlement instance permitted to spend the pool.
    constructor(IERC20 _fxrp, address _settlement) {
        require(address(_fxrp) != address(0), ZeroAddress());
        require(_settlement != address(0), ZeroAddress());
        require(address(_fxrp).code.length > 0, ZeroAddress());
        FXRP = _fxrp;
        SETTLEMENT = _settlement;
        OWNER = msg.sender;
    }

    /// @inheritdoc IPayoutExecutor
    function executePayout(bytes32 _policyId, address _payoutTo, uint256 _amount)
        external
        onlySettlement
    {
        require(_payoutTo != address(0), ZeroAddress());
        require(_amount > 0, ZeroAmount());

        uint256 available = FXRP.balanceOf(address(this));
        // Checked explicitly so an underfunded pool reports what it was short by,
        // instead of surfacing as the token's generic transfer failure.
        require(_amount <= available, InsufficientLiquidity(_amount, available));

        _transfer(_payoutTo, _amount);

        emit PayoutExecuted(_policyId, _payoutTo, _amount);
    }

    /// @notice Take float back out of the pool.
    /// @dev Testnet FXRP is free but not infinite, and a pool with no way out
    ///      would strand it on every redeploy.
    function withdraw(address _to, uint256 _amount) external onlyOwner {
        require(_to != address(0), ZeroAddress());
        require(_amount > 0, ZeroAmount());

        _transfer(_to, _amount);

        emit PoolWithdrawn(_to, _amount);
    }

    /// @inheritdoc IPayoutExecutor
    function payoutDenomination() external view returns (string memory symbol, uint8 decimals) {
        return (FXRP.symbol(), FXRP.decimals());
    }

    /// @inheritdoc IPayoutExecutor
    function availableLiquidity() external view returns (uint256) {
        return FXRP.balanceOf(address(this));
    }

    /// @dev Accepts both ERC-20 dialects: tokens that return a bool and tokens
    ///      that return nothing. FXRP returns a bool today, but a payout that
    ///      silently no-ops because a `false` went unchecked would mark a policy
    ///      paid without paying it.
    function _transfer(address _to, uint256 _amount) private {
        // solhint-disable-next-line avoid-low-level-calls
        (bool ok, bytes memory returned) =
            address(FXRP).call(abi.encodeCall(IERC20.transfer, (_to, _amount)));
        require(ok && (returned.length == 0 || abi.decode(returned, (bool))), TransferFailed());
    }
}
