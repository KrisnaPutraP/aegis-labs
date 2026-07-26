// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

/// @notice The part of ERC-20 the FXRP payout path uses.
/// @dev Declared locally rather than pulled from OpenZeppelin: Aegis has no
///      Solidity dependencies checked in, and adding a submodule to carry six
///      function signatures would cost more than it saves.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
}
