// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

// TODO: Replace this minimal interface with the full import once flare-smart-contracts-v2
// is published as a package:
//   import { ITeeMachineRegistry } from "flare-smart-contracts-v2/contracts/userInterfaces/tee/ITeeMachineRegistry.sol";
interface ITeeMachineRegistry {
    /// @notice Lifecycle of a registered TEE machine. Only PRODUCTION machines
    ///         have completed attestation and are trusted to sign results.
    enum TeeStatus { NONE, INITIALIZED, PRODUCTION, SUSPENDED, PAUSED, BANNED }

    function getRandomTeeIds(uint256 _extensionId, uint256 _count)
        external view returns (address[] memory);

    /// @notice The extension a TEE machine is registered against.
    /// @dev Used by PolicySettlement to check a recovered signer is one of *our*
    ///      enclaves and not some other extension's.
    function getExtensionId(address _teeId) external view returns (uint256);

    /// @notice Current status of a TEE machine.
    function getTeeMachineStatus(address _teeId) external view returns (TeeStatus);
}
