// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

/// @title IPayoutExecutor
/// @notice The seam between a settled policy decision and the money that settles it.
///
/// @dev ARCHITECTURE.md D4 locks the payout component as swappable behind one
///      interface. The MVP implementation moves FXRP on Flare; the roadmap
///      implementation sends real XRP over PMW once FDC2 opens to third-party
///      extensions (TUTORIAL.md §8). Swapping between them must not touch the
///      enclave's EVALUATE handler, so nothing about the asset appears above this
///      line: the enclave signs a policy id, an amount and a recipient, and the
///      executor alone decides what those are denominated in and where the funds
///      come from.
///
///      That is also why the pool lives inside the implementation rather than in
///      a shared vault. The funding source is asset-specific — an ERC-20 balance
///      here, an XRPL wallet under PMW — so one setPayoutExecutor() call has to
///      move the asset and its float together or it moves neither.
interface IPayoutExecutor {
    /// @notice Emitted once per settled claim that actually moved funds.
    event PayoutExecuted(bytes32 indexed policyId, address indexed payoutTo, uint256 amount);

    /// @notice Pay a settled claim.
    /// @dev Implementations MUST revert unless the caller is the settlement
    ///      contract they were deployed against: this function moves pooled funds
    ///      on the strength of a decision the caller has already verified.
    ///      Implementations MUST also revert rather than pay out partially, so a
    ///      settlement either completes or leaves the policy unsettled.
    /// @param _policyId Policy the payout settles, for the audit trail.
    /// @param _payoutTo Recipient, as carried by the TEE-signed decision.
    /// @param _amount Amount in the executor's own denomination, always positive.
    function executePayout(bytes32 _policyId, address _payoutTo, uint256 _amount) external;

    /// @notice What this executor pays in.
    /// @return symbol Human-readable ticker, e.g. "FTestXRP".
    /// @return decimals Places between one unit and one whole token.
    function payoutDenomination() external view returns (string memory symbol, uint8 decimals);

    /// @notice Funds the executor can settle claims from right now, in its own units.
    function availableLiquidity() external view returns (uint256);
}
