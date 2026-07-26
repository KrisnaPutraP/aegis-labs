// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITeeExtensionRegistry } from "../contracts/interfaces/ITeeExtensionRegistry.sol";
import { ITeeMachineRegistry } from "../contracts/interfaces/ITeeMachineRegistry.sol";
import { IPayoutExecutor } from "../contracts/interfaces/IPayoutExecutor.sol";
import { PolicySettlement, IPolicyTriggerRegistry } from "../contracts/PolicySettlement.sol";

/// @title PolicySettlementTest
/// @notice Checks the Solidity half of the TEE action-result signature scheme
///         against a vector produced by the Go half.
///
/// @dev The vector below is the same one asserted in
///      go/tools/pkg/payout/actionresult_test.go, which additionally proves it is
///      what go-ethereum's signer produces for the named key. So: Go says this
///      signature is what a TEE would emit, and this file says PolicySettlement
///      accepts exactly that. Neither side can drift without failing.
///
///      Written without forge-std on purpose — Aegis vendors no Solidity
///      dependencies, and asserting through low-level calls costs a few lines
///      rather than a submodule.
contract PolicySettlementTest {
    // --- golden vector (chain id 31337, forge's default) ---
    address constant TEE_ID = 0x2c7536E3605D9C16a7a3D7b1898e529396a65c23;
    bytes32 constant INSTRUCTION_ID = 0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff;
    string constant SUBMISSION_TAG = "threshold";
    bytes32 constant POLICY_ID = 0x000000000000000000000000000000000000000000000000000000000000a3d1;
    address constant PAYOUT_TO = 0x000000000000000000000000000000000000dEaD;
    uint256 constant PAYOUT_AMOUNT = 3_375_000;
    bytes32 constant SIGN_HASH = 0x444fd3bc85ea62c08bbd6ef5313782b9c3bc05d5fc8e684ee5039667fb52a950;
    bytes constant SIGNATURE =
        hex"9aef68dc04a5445e22a1b605be2ab82e6c4910399176d7869f92a7683bb5f6dc"
        hex"5649079b00ac10f1a7d3bd617ab7207e6ac96c76667b821204c5a2dac892d524"
        hex"01";

    uint256 constant EXTENSION_ID = 65537;

    StubExtensionRegistry extensionRegistry;
    StubMachineRegistry machineRegistry;
    StubInstructionSender instructionSender;
    StubPayoutExecutor executor;
    PolicySettlement settlement;

    function setUp() public {
        instructionSender = new StubInstructionSender();
        extensionRegistry = new StubExtensionRegistry(EXTENSION_ID, address(instructionSender));
        machineRegistry = new StubMachineRegistry();

        settlement = new PolicySettlement(
            ITeeExtensionRegistry(address(extensionRegistry)),
            ITeeMachineRegistry(address(machineRegistry)),
            IPolicyTriggerRegistry(address(instructionSender))
        );
        settlement.setExtensionId();

        executor = new StubPayoutExecutor(address(settlement));
        settlement.setPayoutExecutor(IPayoutExecutor(address(executor)));

        machineRegistry.setMachine(TEE_ID, EXTENSION_ID, ITeeMachineRegistry.TeeStatus.PRODUCTION);
        instructionSender.bind(POLICY_ID, keccak256("some attestation request"));
    }

    // --- signature reconstruction ---

    /// The digest Solidity builds must equal the one Go signed.
    function testSignHashMatchesGoldenVector() public view {
        bytes32 got = settlement.actionResultSignHash(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision());
        require(got == SIGN_HASH, "sign hash does not match the Go vector");
    }

    function testRecoversTheSigningEnclave() public view {
        address got = settlement.recoverTeeId(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE);
        require(got == TEE_ID, "recovered the wrong signer");
    }

    /// Flipping one bit of the decision must break recovery, or a payout amount
    /// could be edited in flight.
    function testTamperedDecisionDoesNotRecoverTheEnclave() public view {
        bytes memory tampered = decision();
        tampered[63] = bytes1(uint8(tampered[63]) + 1);

        address got = settlement.recoverTeeId(INSTRUCTION_ID, 1, SUBMISSION_TAG, tampered, SIGNATURE);
        require(got != TEE_ID, "a tampered decision recovered to the enclave");
    }

    // --- settlement ---

    function testSettlePaysTheDecidedAmount() public {
        settlement.settle(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE);

        require(executor.calls() == 1, "executor was not called exactly once");
        require(executor.lastPolicyId() == POLICY_ID, "wrong policy paid");
        require(executor.lastPayoutTo() == PAYOUT_TO, "wrong recipient");
        require(executor.lastAmount() == PAYOUT_AMOUNT, "wrong amount");

        (bool settled, address payoutTo, uint256 amount, bytes32 instructionId) =
            settlement.settlementOf(POLICY_ID);
        require(settled, "policy not recorded as settled");
        require(payoutTo == PAYOUT_TO, "recorded the wrong recipient");
        require(amount == PAYOUT_AMOUNT, "recorded the wrong amount");
        require(instructionId == INSTRUCTION_ID, "recorded the wrong instruction");
    }

    /// The same signed decision must not pay twice.
    function testReplayIsRejected() public {
        settlement.settle(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE);
        require(!trySettle(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE), "replay succeeded");
        require(executor.calls() == 1, "replay reached the executor");
    }

    /// A decision for a policy this deployment never underwrote must not pay.
    function testUnknownPolicyIsRejected() public {
        StubInstructionSender fresh = new StubInstructionSender();
        StubExtensionRegistry freshRegistry = new StubExtensionRegistry(EXTENSION_ID, address(fresh));
        PolicySettlement isolated = new PolicySettlement(
            ITeeExtensionRegistry(address(freshRegistry)),
            ITeeMachineRegistry(address(machineRegistry)),
            IPolicyTriggerRegistry(address(fresh))
        );
        isolated.setExtensionId();
        isolated.setPayoutExecutor(IPayoutExecutor(address(new StubPayoutExecutor(address(isolated)))));

        (bool ok,) = address(isolated).call(
            abi.encodeCall(PolicySettlement.settle, (INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE))
        );
        require(!ok, "settled a policy with no registered trigger");
    }

    /// An enclave belonging to some other extension must not settle our policies.
    function testForeignEnclaveIsRejected() public {
        machineRegistry.setMachine(TEE_ID, EXTENSION_ID + 1, ITeeMachineRegistry.TeeStatus.PRODUCTION);

        require(!trySettle(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE), "foreign enclave settled");
        require(executor.calls() == 0, "foreign enclave reached the executor");
    }

    /// A machine that has not reached PRODUCTION has not completed attestation.
    function testNonProductionEnclaveIsRejected() public {
        machineRegistry.setMachine(TEE_ID, EXTENSION_ID, ITeeMachineRegistry.TeeStatus.INITIALIZED);

        require(!trySettle(INSTRUCTION_ID, 1, SUBMISSION_TAG, decision(), SIGNATURE), "unattested enclave settled");
        require(executor.calls() == 0, "unattested enclave reached the executor");
    }

    /// A failed action carries no decision, only a log.
    function testRejectsFailedDecision() public {
        require(!trySettle(INSTRUCTION_ID, 0, SUBMISSION_TAG, decision(), SIGNATURE), "failed action settled");
    }

    /// The tag is inside the signed preimage; claiming a different one must fail
    /// recovery rather than settle.
    function testSubmissionTagIsBound() public {
        require(!trySettle(INSTRUCTION_ID, 1, "end", decision(), SIGNATURE), "settled under the wrong tag");
    }

    /// A zero payout still closes the policy, and must not touch the pool.
    /// Recording "evaluated, nothing owed" on-chain is what lets a policyholder
    /// see the model ran, rather than being told it did.
    function testZeroPayoutSettlesWithoutPaying() public {
        instructionSender.bind(ZERO_POLICY_ID, keccak256("wet season request"));

        settlement.settle(ZERO_INSTRUCTION_ID, 1, SUBMISSION_TAG, zeroDecision(), ZERO_SIGNATURE);

        require(executor.calls() == 0, "a zero payout reached the executor");
        (bool settled, address payoutTo, uint256 amount,) = settlement.settlementOf(ZERO_POLICY_ID);
        require(settled, "zero-payout policy was not closed");
        require(amount == 0, "zero-payout policy recorded an amount");
        require(payoutTo == address(0), "zero-payout policy recorded a recipient");
    }

    /// The second golden vector: the same enclave key deciding that a wet-season
    /// policy owes nothing. Also generated by the Go side.
    bytes32 constant ZERO_INSTRUCTION_ID =
        0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;
    bytes32 constant ZERO_POLICY_ID =
        0x000000000000000000000000000000000000000000000000000000000000a3d2;
    bytes32 constant ZERO_SIGN_HASH =
        0x65af0a4074b9b43ae0053c933f0576598b3e74d10e43c65dd6b20daf206e96f3;
    bytes constant ZERO_SIGNATURE =
        hex"50e57e2f88b7f9086509b40e2a84e5f16845b5250ac93ffd146d53633b89592f"
        hex"5e5a08347be92cf84f49906767e49d3845b082d36254175025b26a472ffcabf7"
        hex"00";

    /// Recovery id 0 is the case a naive implementation gets wrong, so the zero
    /// vector doubles as the check that both parities verify.
    function testZeroPayoutVectorRecoversTheSameEnclave() public view {
        bytes32 got = settlement.actionResultSignHash(ZERO_INSTRUCTION_ID, 1, SUBMISSION_TAG, zeroDecision());
        require(got == ZERO_SIGN_HASH, "zero-payout sign hash does not match the Go vector");

        address signer =
            settlement.recoverTeeId(ZERO_INSTRUCTION_ID, 1, SUBMISSION_TAG, zeroDecision(), ZERO_SIGNATURE);
        require(signer == TEE_ID, "zero-payout vector recovered the wrong signer");
    }

    function zeroDecision() internal pure returns (bytes memory) {
        return abi.encode(ZERO_POLICY_ID, uint256(0), PAYOUT_TO);
    }

    // --- helpers ---

    function decision() internal pure returns (bytes memory) {
        return abi.encode(POLICY_ID, PAYOUT_AMOUNT, PAYOUT_TO);
    }

    function trySettle(
        bytes32 _instructionId,
        uint8 _status,
        string memory _tag,
        bytes memory _data,
        bytes memory _signature
    ) internal returns (bool) {
        (bool ok,) = address(settlement).call(
            abi.encodeCall(PolicySettlement.settle, (_instructionId, _status, _tag, _data, _signature))
        );
        return ok;
    }
}

contract StubInstructionSender {
    mapping(bytes32 => bytes32) public policyTriggerRequestHash;

    function bind(bytes32 _policyId, bytes32 _requestHash) external {
        policyTriggerRequestHash[_policyId] = _requestHash;
    }
}

contract StubExtensionRegistry {
    uint256 private immutable EXTENSION_ID;
    address private immutable SENDER;

    constructor(uint256 _extensionId, address _sender) {
        EXTENSION_ID = _extensionId;
        SENDER = _sender;
    }

    function nextPublicExtensionId() external view returns (uint256) {
        return EXTENSION_ID + 1;
    }

    function getTeeExtensionInstructionsSender(uint256 _extensionId) external view returns (address) {
        return _extensionId == EXTENSION_ID ? SENDER : address(0);
    }
}

contract StubMachineRegistry {
    mapping(address => uint256) private extensionIds;
    mapping(address => ITeeMachineRegistry.TeeStatus) private statuses;

    function setMachine(address _teeId, uint256 _extensionId, ITeeMachineRegistry.TeeStatus _status) external {
        extensionIds[_teeId] = _extensionId;
        statuses[_teeId] = _status;
    }

    function getExtensionId(address _teeId) external view returns (uint256) {
        return extensionIds[_teeId];
    }

    function getTeeMachineStatus(address _teeId) external view returns (ITeeMachineRegistry.TeeStatus) {
        return statuses[_teeId];
    }
}

contract StubPayoutExecutor is IPayoutExecutor {
    address private immutable SETTLEMENT;

    uint256 public calls;
    bytes32 public lastPolicyId;
    address public lastPayoutTo;
    uint256 public lastAmount;

    constructor(address _settlement) {
        SETTLEMENT = _settlement;
    }

    function executePayout(bytes32 _policyId, address _payoutTo, uint256 _amount) external {
        require(msg.sender == SETTLEMENT, "not settlement");
        calls += 1;
        lastPolicyId = _policyId;
        lastPayoutTo = _payoutTo;
        lastAmount = _amount;
        emit PayoutExecuted(_policyId, _payoutTo, _amount);
    }

    function payoutDenomination() external pure returns (string memory, uint8) {
        return ("STUB", 6);
    }

    function availableLiquidity() external pure returns (uint256) {
        return type(uint256).max;
    }
}
