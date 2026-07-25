// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

import { IWeb2Json } from "./IWeb2Json.sol";

// Minimal local view of Flare's FdcVerification contract, following the same
// pattern as the TEE registry interfaces in this folder.
//
// TODO: Replace with the upstream import once flare-smart-contracts-v2 is published:
//   import { IFdcVerification } from "flare-smart-contracts-v2/contracts/userInterfaces/IFdcVerification.sol";
//
// Upstream splits the verification methods per attestation type
// (IWeb2JsonVerification et al.); Aegis only ever verifies Web2Json, so only that
// method is declared here. The signature is copied verbatim from
// contracts/userInterfaces/fdc/IWeb2JsonVerification.sol.
//
// Reference: https://dev.flare.network/fdc/reference/IFdcVerification
interface IFdcVerification {
    /// @notice Checks a Web2Json attestation against the Merkle root the FDC
    /// finalized for `_proof.data.votingRound`.
    /// @return _proved True only if the response is part of that round's Merkle tree.
    function verifyWeb2Json(IWeb2Json.Proof calldata _proof) external view returns (bool _proved);
}
