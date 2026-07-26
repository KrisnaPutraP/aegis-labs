// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITeeExtensionRegistry } from "./interfaces/ITeeExtensionRegistry.sol";
import { ITeeMachineRegistry } from "./interfaces/ITeeMachineRegistry.sol";
import { IPayoutExecutor } from "./interfaces/IPayoutExecutor.sol";

/// @notice The one thing settlement needs from InstructionSender: whether a
///         policy was ever bound to an FDC attestation request.
interface IPolicyTriggerRegistry {
    function policyTriggerRequestHash(bytes32 _policyId) external view returns (bytes32);
}

/// @title PolicySettlement
/// @author Acex
/// @notice Turns a TEE-signed payout decision into money, verifiably, on-chain.
///
/// @dev This closes the loop ARCHITECTURE.md §3 invariant 2 asks for: *every*
///      payout decision is checkable on-chain against the TEE identity that made
///      it. Nothing here trusts the caller. Anyone may submit a decision — a
///      policyholder, the insurer, a bot — because the signature is what carries
///      the authority, not the sender.
///
///      Why the decision is safe to act on. The enclave signs action results and
///      nothing else, and the only way to make it produce an EVALUATE result is
///      InstructionSender.evaluate, which forwards a reading only after checking
///      the FDC attestation is the one the policy was bound to, is Merkle-proven
///      against its round's on-chain root, and comes from a later round than the
///      previous one. The TEE proxy exposes no public endpoint that queues work
///      (its /direct route is disabled by default and gated by an API key), so a
///      signature over 96 decodable bytes cannot exist without an attested
///      evaluation having happened first.
///
///      Deliberately NOT in this contract: any notion of what the payout is
///      denominated in, or where the funds sit. That is the executor's business
///      (IPayoutExecutor), which is what lets FXRP be swapped for PMW later
///      without redeploying this contract, InstructionSender, or the enclave.
contract PolicySettlement {
    /// @notice Domain separator the TEE node puts in front of an action result
    ///         signature.
    /// @dev Must stay byte-identical to go-flare-common's
    ///      signing.TEEActionResult prefix, which is the UTF-8 string
    ///      left-aligned in 32 bytes — exactly what bytes32("...") produces.
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes32 public constant TEE_ACTION_RESULT_PREFIX = bytes32("TEE_ACTION_RESULT");

    /// @notice Half the secp256k1 group order, the bound on a canonical `s`.
    bytes32 private constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice First public extension ID, mirroring InstructionSender.
    uint256 private constant FIRST_PUBLIC_EXTENSION_ID = 0x10000; // 65536

    /// @notice Reference to the TEE extension registry contract.
    ITeeExtensionRegistry public immutable TEE_EXTENSION_REGISTRY;
    /// @notice Reference to the TEE machine registry contract.
    ITeeMachineRegistry public immutable TEE_MACHINE_REGISTRY;
    /// @notice The Aegis instruction sender whose policies this contract settles.
    IPolicyTriggerRegistry public immutable INSTRUCTION_SENDER;

    /// @notice Deployer. May point settlement at a different payout executor.
    address public immutable OWNER;

    uint256 private _extensionId;

    /// @notice Where settled claims are paid from. The swap point for D4.
    IPayoutExecutor public payoutExecutor;

    /// @notice What a settled policy was settled as.
    /// @param settled Whether the policy has been closed out.
    /// @param payoutTo Recipient the enclave named, zero when nothing was owed.
    /// @param amount Amount paid, zero when the model did not trigger.
    /// @param instructionId Evaluation that produced the decision.
    struct Settlement {
        bool settled;
        address payoutTo;
        uint256 amount;
        bytes32 instructionId;
    }

    /// @notice policyId => how it was settled.
    mapping(bytes32 => Settlement) public settlementOf;

    /// @notice instructionId => already consumed.
    /// @dev A second guard behind the per-policy one. It costs one slot and it
    ///      means a replayed decision is rejected as a replay, not as "policy
    ///      already settled", which is the difference between reading the revert
    ///      and guessing at it.
    mapping(bytes32 => bool) public decisionSettled;

    /// @notice Emitted for every policy closed out, paying or not.
    event PolicySettled(
        bytes32 indexed policyId,
        bytes32 indexed instructionId,
        address indexed teeId,
        address payoutTo,
        uint256 amount
    );

    /// @notice Emitted when the payout implementation behind D4 is swapped.
    event PayoutExecutorChanged(address indexed previous, address indexed current);

    error NotOwner();
    error ZeroAddress();
    error ExtensionIdNotSet();
    error ExtensionIdAlreadySet();
    error ExtensionIdNotFound();
    error DecisionFailed();
    error MalformedDecision(uint256 length);
    error MalformedSignature();
    error NotOurEnclave(address teeId, uint256 extensionId);
    error EnclaveNotInProduction(address teeId, ITeeMachineRegistry.TeeStatus status);
    error DecisionAlreadySettled(bytes32 instructionId);
    error PolicyAlreadySettled(bytes32 policyId);
    error UnknownPolicy(bytes32 policyId);
    error NoPayoutExecutor();

    modifier onlyOwner() {
        require(msg.sender == OWNER, NotOwner());
        _;
    }

    /// @param _teeExtensionRegistry Address of the TEE extension registry.
    /// @param _teeMachineRegistry Address of the TEE machine registry.
    /// @param _instructionSender The deployed Aegis InstructionSender.
    constructor(
        ITeeExtensionRegistry _teeExtensionRegistry,
        ITeeMachineRegistry _teeMachineRegistry,
        IPolicyTriggerRegistry _instructionSender
    ) {
        require(address(_teeExtensionRegistry).code.length > 0, ZeroAddress());
        require(address(_teeMachineRegistry).code.length > 0, ZeroAddress());
        require(address(_instructionSender).code.length > 0, ZeroAddress());
        TEE_EXTENSION_REGISTRY = _teeExtensionRegistry;
        TEE_MACHINE_REGISTRY = _teeMachineRegistry;
        INSTRUCTION_SENDER = _instructionSender;
        OWNER = msg.sender;
    }

    /// @notice Find and cache the extension id InstructionSender was registered
    ///         under. Can only be set once.
    /// @dev The same scan InstructionSender.setExtensionId does, but resolving
    ///      *its* address rather than this one's. Doing it here keeps settlement
    ///      an add-on: InstructionSender needs no new function, so the deployed
    ///      extension and its registered TEE are left untouched.
    function setExtensionId() external {
        require(_extensionId == 0, ExtensionIdAlreadySet());

        uint256 c = TEE_EXTENSION_REGISTRY.nextPublicExtensionId();
        for (uint256 i = FIRST_PUBLIC_EXTENSION_ID; i < c; ++i) {
            if (TEE_EXTENSION_REGISTRY.getTeeExtensionInstructionsSender(i) == address(INSTRUCTION_SENDER)) {
                _extensionId = i;
                return;
            }
        }
        revert ExtensionIdNotFound();
    }

    /// @notice Point settlement at a different payout implementation.
    /// @dev This is the whole of ARCHITECTURE.md D4's swappability. Moving from
    ///      FXRP to PMW is one call here; the enclave, InstructionSender and every
    ///      already-settled policy are unaffected. Policies settled under the old
    ///      executor stay settled — the record is in this contract, not in the
    ///      executor.
    function setPayoutExecutor(IPayoutExecutor _payoutExecutor) external onlyOwner {
        require(address(_payoutExecutor).code.length > 0, ZeroAddress());

        emit PayoutExecutorChanged(address(payoutExecutor), address(_payoutExecutor));
        payoutExecutor = _payoutExecutor;
    }

    /// @notice Settle a policy against the enclave's signed decision.
    ///
    /// @dev The five arguments are the fields of the tee-node ActionResult that
    ///      its signature actually covers, in the order they are hashed. They are
    ///      passed in rather than read from anywhere because there is nowhere to
    ///      read them from: the result lives off-chain, served by the TEE proxy,
    ///      and the signature is what makes relaying it trustless.
    ///
    ///      Permissionless by design. The caller pays the gas and gains nothing:
    ///      the recipient and the amount are both inside the signed payload.
    ///
    /// @param _instructionId The evaluation's instruction id (ActionResult.ID).
    /// @param _status ActionResult.Status — 1 for success, 0 for failure.
    /// @param _submissionTag ActionResult.SubmissionTag, e.g. "threshold".
    /// @param _data ActionResult.Data: abi.encode(policyId, payoutAmount, payoutTo).
    /// @param _signature 65-byte TEE identity signature, r ‖ s ‖ v with v in {0,1}.
    function settle(
        bytes32 _instructionId,
        uint8 _status,
        string calldata _submissionTag,
        bytes calldata _data,
        bytes calldata _signature
    ) external {
        // A failed action carries no decision — its Data is empty and its Log
        // says why. Paying on one would pay on an enclave error.
        require(_status == 1, DecisionFailed());
        require(_data.length == 96, MalformedDecision(_data.length));

        address teeId = _recoverTeeId(_instructionId, _status, _submissionTag, _data, _signature);

        uint256 ourExtensionId = _getExtensionId();
        uint256 signerExtensionId = TEE_MACHINE_REGISTRY.getExtensionId(teeId);
        // Any enclave in the Flare TEE fleet can sign; only ours runs the model
        // these policies were underwritten with.
        require(signerExtensionId == ourExtensionId, NotOurEnclave(teeId, signerExtensionId));

        ITeeMachineRegistry.TeeStatus status = TEE_MACHINE_REGISTRY.getTeeMachineStatus(teeId);
        require(
            status == ITeeMachineRegistry.TeeStatus.PRODUCTION,
            EnclaveNotInProduction(teeId, status)
        );

        require(!decisionSettled[_instructionId], DecisionAlreadySettled(_instructionId));

        (bytes32 policyId, uint256 amount, address payoutTo) =
            abi.decode(_data, (bytes32, uint256, address));

        // A policy that was never bound to an attestation request is not a policy
        // this deployment underwrote.
        require(
            INSTRUCTION_SENDER.policyTriggerRequestHash(policyId) != bytes32(0),
            UnknownPolicy(policyId)
        );
        require(!settlementOf[policyId].settled, PolicyAlreadySettled(policyId));

        // A parametric policy pays once and closes. Re-evaluating it later reads
        // the same bound feed over the same window, so a second decision says the
        // same thing; recording the first is what stops it from paying twice.
        //
        // State is written before the payout call: nothing an executor does can
        // re-enter and settle this policy again.
        decisionSettled[_instructionId] = true;
        settlementOf[policyId] = Settlement({
            settled: true,
            payoutTo: amount > 0 ? payoutTo : address(0),
            amount: amount,
            instructionId: _instructionId
        });

        if (amount > 0) {
            IPayoutExecutor executor = payoutExecutor;
            require(address(executor) != address(0), NoPayoutExecutor());
            executor.executePayout(policyId, payoutTo, amount);
        }

        emit PolicySettled(policyId, _instructionId, teeId, payoutTo, amount);
    }

    /// @notice The extension id this contract settles for.
    function extensionId() external view returns (uint256) {
        return _getExtensionId();
    }

    /// @notice Recover which TEE identity signed an action result.
    /// @dev Exposed as a view so the signature reconstruction can be tested and
    ///      debugged directly, rather than only through a settlement that also
    ///      touches registries and balances.
    function recoverTeeId(
        bytes32 _instructionId,
        uint8 _status,
        string calldata _submissionTag,
        bytes calldata _data,
        bytes calldata _signature
    ) external view returns (address) {
        return _recoverTeeId(_instructionId, _status, _submissionTag, _data, _signature);
    }

    /// @notice The digest the TEE signs over an action result, before the
    ///         Ethereum Signed Message wrapper.
    /// @dev Mirrors tee-node: signing.Payload{TEE_ACTION_RESULT, chainId,
    ///      ActionResult.Hash()}.Hash(). Payload is a static tuple, so its ABI
    ///      encoding is just the three words concatenated.
    function actionResultSignHash(
        bytes32 _instructionId,
        uint8 _status,
        string calldata _submissionTag,
        bytes calldata _data
    ) public view returns (bytes32) {
        // ActionResult.Hash(): keccak256(keccak256(data) ‖ id ‖ keccak256(tag) ‖ status)
        bytes32 resultHash = keccak256(
            abi.encodePacked(keccak256(_data), _instructionId, keccak256(bytes(_submissionTag)), _status)
        );

        return keccak256(abi.encode(TEE_ACTION_RESULT_PREFIX, block.chainid, resultHash));
    }

    function _recoverTeeId(
        bytes32 _instructionId,
        uint8 _status,
        string calldata _submissionTag,
        bytes calldata _data,
        bytes calldata _signature
    ) private view returns (address) {
        require(_signature.length == 65, MalformedSignature());

        bytes32 signHash = actionResultSignHash(_instructionId, _status, _submissionTag, _data);
        // go-ethereum signs accounts.TextHash(signHash), i.e. the EIP-191
        // personal-message wrapper over the 32-byte digest.
        bytes32 ethSignedHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", signHash));

        bytes32 r = bytes32(_signature[0:32]);
        bytes32 s = bytes32(_signature[32:64]);
        uint8 v = uint8(_signature[64]);
        // The TEE node emits go-ethereum's recovery id (0 or 1); ecrecover wants
        // 27 or 28. Tolerate both so a signature that has already been converted
        // still verifies.
        if (v < 27) {
            v += 27;
        }

        // Reject the malleable half of the curve. Replay protection here keys on
        // the instruction id rather than the signature, so this is belt and
        // braces, but a flipped signature recovering to a junk address would
        // report as "not our enclave" and send the operator hunting the wrong bug.
        require(uint256(s) <= uint256(SECP256K1_HALF_N), MalformedSignature());
        require(v == 27 || v == 28, MalformedSignature());

        address teeId = ecrecover(ethSignedHash, v, r, s);
        require(teeId != address(0), MalformedSignature());

        return teeId;
    }

    function _getExtensionId() private view returns (uint256) {
        require(_extensionId != 0, ExtensionIdNotSet());
        return _extensionId;
    }
}
