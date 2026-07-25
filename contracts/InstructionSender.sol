// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// TODO: Replace local interfaces with imports from flare-smart-contracts-v2 once published as a package.
import { ITeeExtensionRegistry } from "./interfaces/ITeeExtensionRegistry.sol";
import { ITeeMachineRegistry } from "./interfaces/ITeeMachineRegistry.sol";
import { IFdcVerification } from "./interfaces/IFdcVerification.sol";
import { IWeb2Json } from "./interfaces/IWeb2Json.sol";

/// @title InstructionSender (Aegis policy extension)
/// @author Acex
/// @notice On-chain entry point for sending policy instructions to the Aegis TEE.
///
/// @dev This contract is the only address the TEE extension registry accepts instructions
///      from for this extension (`ITeeExtensionRegistry.OnlyInstructionsSender`). That makes
///      it the trust gate for the enclave: whatever this contract refuses to forward can
///      never reach the model. Every EVALUATE therefore carries an FDC Web2Json attestation
///      that is Merkle-verified here first, which is what satisfies trust boundary invariant 3
///      in ARCHITECTURE.md §3 — the enclave only ever scores FDC-attested weather data.
///
/// DO NOT MODIFY: the registry wiring in the constructor, setExtensionId(), _getExtensionId()
contract InstructionSender {
    /// @notice Operation type for policy actions (REGISTER_MODEL, EVALUATE).
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant OP_TYPE_POLICY = bytes32("POLICY");

    /// @notice Command for the REGISTER_MODEL action (loads an insurer's encrypted risk model).
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant OP_COMMAND_REGISTER_MODEL = bytes32("REGISTER_MODEL");

    /// @notice Command for the EVALUATE action (scores attested trigger data against the hidden model).
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant OP_COMMAND_EVALUATE = bytes32("EVALUATE");

    /// @notice Reference to the TEE extension registry contract.
    ITeeExtensionRegistry public immutable TEE_EXTENSION_REGISTRY;
    /// @notice Reference to the TEE machine registry contract.
    ITeeMachineRegistry public immutable TEE_MACHINE_REGISTRY;
    /// @notice Flare's FdcVerification contract — checks a Web2Json attestation against the
    ///         Merkle root its voting round finalized.
    IFdcVerification public immutable FDC_VERIFICATION;

    /// @notice First public extension ID. The registry reserves IDs below this
    /// for system/reserved extensions; public extensions are assigned from here up.
    uint256 private constant FIRST_PUBLIC_EXTENSION_ID = 0x10000; // 65536

    uint256 private _extensionId;

    /// @notice Deployer. Registers which attested feed each policy is allowed to be scored on.
    address public immutable OWNER;

    /// @notice The shape the policy's jq filter must produce, and what
    ///         `IWeb2Json.ResponseBody.abiEncodedData` decodes to.
    /// @param latitudeMicroDeg Latitude the weather source reported, in degrees x 1e6.
    /// @param longitudeMicroDeg Longitude the weather source reported, in degrees x 1e6.
    /// @param rainfallTenthsMm Cumulative rainfall over the policy window, in tenths of a mm.
    struct WeatherReading {
        int256 latitudeMicroDeg;
        int256 longitudeMicroDeg;
        uint256 rainfallTenthsMm;
    }

    /// @notice policyId => keccak256(abi.encode(IWeb2Json.RequestBody)) of the one attestation
    ///         request that may settle it.
    /// @dev Binding the whole request body — not just the coordinates — is what stops an
    ///      attacker from settling a policy with a genuine attestation of some *other* query:
    ///      another location, another date window, or a jq filter that reports a convenient
    ///      number. A valid Merkle proof alone proves the data was attested, not that it is
    ///      the data this policy was underwritten against.
    mapping(bytes32 => bytes32) public policyTriggerRequestHash;

    /// @notice policyId => voting round of the most recent attestation accepted for it.
    /// @dev Evaluations must move forward, so a stale round cannot be replayed later.
    mapping(bytes32 => uint64) public lastAttestedVotingRound;

    /// @notice Emitted when a policy is bound to the attestation request that may settle it.
    event PolicyTriggerRegistered(bytes32 indexed policyId, bytes32 requestBodyHash);

    /// @notice Emitted for every EVALUATE forwarded to the TEE, recording exactly which
    ///         attested reading the enclave was asked to score.
    event PolicyEvaluationRequested(
        bytes32 indexed policyId,
        bytes32 indexed instructionId,
        uint64 votingRound,
        int256 latitudeMicroDeg,
        int256 longitudeMicroDeg,
        uint256 rainfallTenthsMm
    );

    modifier onlyOwner() {
        require(msg.sender == OWNER, "not owner");
        _;
    }

    /// @notice Initializes the contract with registry addresses.
    /// @param _teeExtensionRegistry Address of the TEE extension registry.
    /// @param _teeMachineRegistry Address of the TEE machine registry.
    /// @param _fdcVerification Address of Flare's FdcVerification contract.
    constructor(
        ITeeExtensionRegistry _teeExtensionRegistry,
        ITeeMachineRegistry _teeMachineRegistry,
        IFdcVerification _fdcVerification
    ) {
        require(address(_teeExtensionRegistry) != address(0), "TeeExtensionRegistry cannot be zero address");
        require(address(_teeMachineRegistry) != address(0), "TeeMachineRegistry cannot be zero address");
        require(address(_teeExtensionRegistry).code.length > 0, "TeeExtensionRegistry has no code");
        require(address(_teeMachineRegistry).code.length > 0, "TeeMachineRegistry has no code");
        require(address(_fdcVerification) != address(0), "FdcVerification cannot be zero address");
        require(address(_fdcVerification).code.length > 0, "FdcVerification has no code");
        TEE_EXTENSION_REGISTRY = _teeExtensionRegistry;
        TEE_MACHINE_REGISTRY = _teeMachineRegistry;
        FDC_VERIFICATION = _fdcVerification;
        OWNER = msg.sender;
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

    /// @notice Bind a policy to the single FDC attestation request whose result may settle it.
    /// @dev Write-once and owner-only: the insurer underwrites against a specific feed (source
    ///      URL, query, jq filter, decoding signature), and nobody — including the insurer —
    ///      may point a live policy at a different one afterwards.
    /// @param _policyId Policy identifier, the same one used with REGISTER_MODEL.
    /// @param _requestBodyHash keccak256(abi.encode(IWeb2Json.RequestBody)) of that request.
    ///        Compute it off-chain, or with `triggerRequestHash` below.
    function registerPolicyTrigger(bytes32 _policyId, bytes32 _requestBodyHash) external onlyOwner {
        require(_policyId != bytes32(0), "policyId cannot be zero");
        require(_requestBodyHash != bytes32(0), "requestBodyHash cannot be zero");
        require(policyTriggerRequestHash[_policyId] == bytes32(0), "policy trigger already registered");

        policyTriggerRequestHash[_policyId] = _requestBodyHash;
        emit PolicyTriggerRegistered(_policyId, _requestBodyHash);
    }

    /// @notice Ask the TEE to score a policy's attested rainfall against its hidden model.
    /// @dev There is deliberately no way to hand the enclave a rainfall figure directly. The
    ///      reading comes out of `_proof`, and the proof has to clear three checks first:
    ///      it must be the request this policy was bound to, the FDC must have finalized it
    ///      (Merkle proof against the round's root), and its round must be newer than the last
    ///      one accepted for the policy. Only then is the extracted reading forwarded.
    ///
    ///      Everything forwarded is public: the weather reading is public data and the
    ///      decision is meant to be verified on-chain. The model that turns one into the
    ///      other never leaves the enclave.
    /// @param _policyId Policy identifier, as registered with the TEE.
    /// @param _payoutTo Address that receives the payout if the model triggers one.
    /// @param _proof FDC Web2Json attestation of the policy's weather feed, as returned by the
    ///        Data Availability Layer.
    function evaluate(bytes32 _policyId, address _payoutTo, IWeb2Json.Proof calldata _proof) external payable {
        bytes32 expectedRequestHash = policyTriggerRequestHash[_policyId];
        require(expectedRequestHash != bytes32(0), "policy trigger not registered");
        require(
            keccak256(abi.encode(_proof.data.requestBody)) == expectedRequestHash,
            "attestation is not this policy's trigger"
        );
        require(FDC_VERIFICATION.verifyWeb2Json(_proof), "invalid FDC attestation");
        require(
            _proof.data.votingRound > lastAttestedVotingRound[_policyId],
            "attestation older than last evaluation"
        );
        lastAttestedVotingRound[_policyId] = _proof.data.votingRound;

        WeatherReading memory reading = abi.decode(_proof.data.responseBody.abiEncodedData, (WeatherReading));

        address[] memory teeIds = TEE_MACHINE_REGISTRY.getRandomTeeIds(_getExtensionId(), 1);
        address[] memory cosigners = new address[](0);

        ITeeExtensionRegistry.TeeInstructionParams memory params = ITeeExtensionRegistry.TeeInstructionParams({
            opType: OP_TYPE_POLICY,
            opCommand: OP_COMMAND_EVALUATE,
            message: abi.encode(_policyId, reading.rainfallTenthsMm, _payoutTo),
            cosigners: cosigners,
            cosignersThreshold: 0,
            claimBackAddress: msg.sender
        });

        bytes32 instructionId = TEE_EXTENSION_REGISTRY.sendInstructions{value: msg.value}(
            teeIds,
            params
        );

        emit PolicyEvaluationRequested(
            _policyId,
            instructionId,
            _proof.data.votingRound,
            reading.latitudeMicroDeg,
            reading.longitudeMicroDeg,
            reading.rainfallTenthsMm
        );
    }

    /// @notice Hash of an attestation request body, in the exact form `evaluate` compares against.
    /// @dev Lets the insurer register a trigger from the same request they hand the FDC verifier,
    ///      instead of re-implementing abi.encode off-chain and hoping the two agree.
    function triggerRequestHash(IWeb2Json.RequestBody calldata _requestBody) external pure returns (bytes32) {
        return keccak256(abi.encode(_requestBody));
    }

    /// @notice Never called. It exists so `WeatherReading` appears in this contract's ABI, which
    ///         is how off-chain tooling learns the struct the policy's jq filter must produce.
    ///         Flare's own Web2Json guide uses the same idiom.
    // solhint-disable-next-line no-empty-blocks
    function weatherReadingAbi(WeatherReading memory _reading) external pure {}

    /// @notice Returns the cached extension ID, reverting if not yet set.
    /// @return The extension ID assigned to this contract.
    function _getExtensionId() internal view returns (uint256) {
        require(_extensionId != 0, "Extension ID is not set.");
        return _extensionId;
    }
}
