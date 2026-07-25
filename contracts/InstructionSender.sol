// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// TODO: Replace local interfaces with imports from flare-smart-contracts-v2 once published as a package.
import { ITeeExtensionRegistry } from "./interfaces/ITeeExtensionRegistry.sol";
import { ITeeMachineRegistry } from "./interfaces/ITeeMachineRegistry.sol";

/// @title InstructionSender (Aegis policy extension)
/// @author Acex
/// @notice On-chain entry point for sending policy instructions to the Aegis TEE.
///
/// DO NOT MODIFY: constructor, setExtensionId(), _getExtensionId()
contract InstructionSender {
    /// @notice Operation type for policy actions (REGISTER_MODEL, EVALUATE).
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant OP_TYPE_POLICY = bytes32("POLICY");

    /// @notice Command for the REGISTER_MODEL action (loads an insurer's encrypted risk model).
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant OP_COMMAND_REGISTER_MODEL = bytes32("REGISTER_MODEL");

    /// @notice Command for the EVALUATE action (scores trigger data against the hidden model).
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant OP_COMMAND_EVALUATE = bytes32("EVALUATE");

    /// @notice Reference to the TEE extension registry contract.
    ITeeExtensionRegistry public immutable TEE_EXTENSION_REGISTRY;
    /// @notice Reference to the TEE machine registry contract.
    ITeeMachineRegistry public immutable TEE_MACHINE_REGISTRY;

    /// @notice First public extension ID. The registry reserves IDs below this
    /// for system/reserved extensions; public extensions are assigned from here up.
    uint256 private constant FIRST_PUBLIC_EXTENSION_ID = 0x10000; // 65536

    uint256 private _extensionId;

    /// @notice Initializes the contract with registry addresses.
    /// @param _teeExtensionRegistry Address of the TEE extension registry.
    /// @param _teeMachineRegistry Address of the TEE machine registry.
    constructor(
        ITeeExtensionRegistry _teeExtensionRegistry,
        ITeeMachineRegistry _teeMachineRegistry
    ) {
        require(address(_teeExtensionRegistry) != address(0), "TeeExtensionRegistry cannot be zero address");
        require(address(_teeMachineRegistry) != address(0), "TeeMachineRegistry cannot be zero address");
        require(address(_teeExtensionRegistry).code.length > 0, "TeeExtensionRegistry has no code");
        require(address(_teeMachineRegistry).code.length > 0, "TeeMachineRegistry has no code");
        TEE_EXTENSION_REGISTRY = _teeExtensionRegistry;
        TEE_MACHINE_REGISTRY = _teeMachineRegistry;
    }

    /// @notice Finds and sets this contract's extension id. Can only be set once.
    /// DO NOT MODIFY this function.
    function setExtensionId() external {
        require(_extensionId == 0, "Extension ID already set.");

        uint256 c = TEE_EXTENSION_REGISTRY.nextPublicExtensionId();
        for (uint256 i = FIRST_PUBLIC_EXTENSION_ID; i < c; ++i) {
            if (TEE_EXTENSION_REGISTRY.getTeeExtensionInstructionsSender(i) == address(this)) {
                _extensionId = i;
                return;
            }
        }
        revert("Extension ID not found.");
    }

    /// @notice Load an insurer's confidential risk model for one policy into the TEE.
    /// @dev The payload stays opaque on-chain by design: it is ECIES ciphertext sealed to the
    ///      enclave public key, and only the enclave can open it. Never pass plaintext model
    ///      parameters here — on-chain data is public forever (ARCHITECTURE.md §3).
    /// @param _encryptedModel ECIES-encrypted JSON RegisterModelRequest (policy id + parameters).
    function registerModel(bytes calldata _encryptedModel) external payable {
        address[] memory teeIds = TEE_MACHINE_REGISTRY.getRandomTeeIds(_getExtensionId(), 1);
        address[] memory cosigners = new address[](0);

        ITeeExtensionRegistry.TeeInstructionParams memory params = ITeeExtensionRegistry.TeeInstructionParams({
            opType: OP_TYPE_POLICY,
            opCommand: OP_COMMAND_REGISTER_MODEL,
            message: _encryptedModel,
            cosigners: cosigners,
            cosignersThreshold: 0,
            claimBackAddress: msg.sender
        });

        TEE_EXTENSION_REGISTRY.sendInstructions{value: msg.value}(
            teeIds,
            params
        );
    }

    /// @notice Ask the TEE to score trigger data for a policy against its hidden model.
    /// @dev Every argument is public: the weather reading is public data and the decision is
    ///      meant to be verified on-chain. Fase 3 replaces the caller-supplied reading with a
    ///      value carried by an FDC JsonApi attestation, so that evaluation can only ever run on
    ///      attested data (trust boundary invariant 3).
    /// @param _policyId Policy identifier, as registered with the TEE.
    /// @param _rainfallTenthsMm Cumulative rainfall over the policy window, in tenths of a mm.
    /// @param _payoutTo Address that receives the payout if the model triggers one.
    function evaluate(bytes32 _policyId, uint256 _rainfallTenthsMm, address _payoutTo) external payable {
        address[] memory teeIds = TEE_MACHINE_REGISTRY.getRandomTeeIds(_getExtensionId(), 1);
        address[] memory cosigners = new address[](0);

        ITeeExtensionRegistry.TeeInstructionParams memory params = ITeeExtensionRegistry.TeeInstructionParams({
            opType: OP_TYPE_POLICY,
            opCommand: OP_COMMAND_EVALUATE,
            message: abi.encode(_policyId, _rainfallTenthsMm, _payoutTo),
            cosigners: cosigners,
            cosignersThreshold: 0,
            claimBackAddress: msg.sender
        });

        TEE_EXTENSION_REGISTRY.sendInstructions{value: msg.value}(
            teeIds,
            params
        );
    }

    /// @notice Returns the cached extension ID, reverting if not yet set.
    /// @return The extension ID assigned to this contract.
    function _getExtensionId() internal view returns (uint256) {
        require(_extensionId != 0, "Extension ID is not set.");
        return _extensionId;
    }
}
