// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

// Verbatim copy of the Web2Json attestation type as published by Flare, kept local
// for the same reason as the TEE registry interfaces: flare-smart-contracts-v2 is
// not published as a package yet.
//
// TODO: Replace with the upstream import once available:
//   import { IWeb2Json } from "flare-smart-contracts-v2/contracts/userInterfaces/fdc/IWeb2Json.sol";
//
// Source: https://github.com/flare-foundation/flare-smart-contracts-v2
//         contracts/userInterfaces/fdc/IWeb2Json.sol
// Spec:   https://dev.flare.network/fdc/attestation-types/web2-json
//
// The struct layout MUST stay byte-identical to the upstream one: FdcVerification
// hashes the ABI encoding of `Response` and checks it against the Merkle root the
// FDC voting round finalized. A reordered or renamed field silently breaks every
// proof.

/**
 * @custom:name IWeb2Json
 * @custom:supported WEB2
 * @custom:id 0x06
 * @author Flare
 * @notice An attestation request that fetches JSON data from the given URL,
 * applies a jq filter to transform the returned result, and returns the structured data as ABI encoded data.
 */
interface IWeb2Json {
    /**
     * @notice Toplevel request
     * @param attestationType ID of the attestation type.
     * @param sourceId ID of the data source.
     * @param messageIntegrityCode `MessageIntegrityCode` that is derived from the expected response.
     * @param requestBody Data defining the request.
     */
    struct Request {
        bytes32 attestationType;
        bytes32 sourceId;
        bytes32 messageIntegrityCode;
        RequestBody requestBody;
    }

    /**
     * @notice Toplevel response
     * @param attestationType Extracted from the request.
     * @param sourceId Extracted from the request.
     * @param votingRound The ID of the State Connector round in which the request was considered.
     * @param lowestUsedTimestamp The lowest timestamp used to generate the response.
     * @param requestBody Extracted from the request.
     * @param responseBody Data defining the response.
     */
    struct Response {
        bytes32 attestationType;
        bytes32 sourceId;
        uint64 votingRound;
        uint64 lowestUsedTimestamp;
        RequestBody requestBody;
        ResponseBody responseBody;
    }

    /**
     * @notice Toplevel proof
     * @param merkleProof Merkle proof corresponding to the attestation response.
     * @param data Attestation response.
     */
    struct Proof {
        bytes32[] merkleProof;
        Response data;
    }

    /**
     * @notice Request body for Web2Json attestation type
     * @param url URL of the data source
     * @param httpMethod HTTP method to be used to fetch from URL source.
     * @param headers Headers to be included to fetch from URL source. Use `{}` if no headers are needed.
     * @param queryParams Query parameters to be included to fetch from URL source.
     * @param body Request body to be included to fetch from URL source. Use '{}' if no request body is required.
     * @param postProcessJq jq filter used to post-process the JSON response from the URL.
     * @param abiSignature ABI signature of the struct used to encode the data after jq post-processing.
     */
    struct RequestBody {
        string url;
        string httpMethod;
        string headers;
        string queryParams;
        string body;
        string postProcessJq;
        string abiSignature;
    }

    /**
     * @notice Response body for Web2Json attestation type
     * @param abiEncodedData Raw binary data encoded to match the function parameters in ABI.
     */
    struct ResponseBody {
        bytes abiEncodedData;
    }
}
