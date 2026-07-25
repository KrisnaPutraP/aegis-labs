// Package fdc drives the Flare Data Connector's Web2Json attestation flow, which
// is how Aegis gets weather data it can prove on-chain.
//
// One attestation takes four steps, and they are deliberately kept separate here
// because the third one costs real time:
//
//  1. PrepareRequest  — a verifier server fetches the API, applies the policy's jq
//     filter, and returns the ABI-encoded request plus a message integrity code.
//  2. SubmitRequest   — that request goes to FdcHub on Coston2, which schedules it
//     into the voting round the submitting block falls in.
//  3. (wait)          — data providers attest and finalize the round's Merkle root,
//     which takes 90–180 seconds.
//  4. WaitForProof    — a Data Availability Layer provider serves the attested
//     response together with its Merkle proof.
//
// The proof is then passed to InstructionSender.evaluate, which re-checks it
// against the on-chain Merkle root before the enclave ever sees the reading.
//
// References:
//   - https://dev.flare.network/fdc/guides/foundry/web2-json
//   - https://dev.flare.network/fdc/attestation-types/web2-json
package fdc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

const (
	// AttestationTypeWeb2Json is the attestation type name, UTF-8 hex encoded and
	// zero-padded to 32 bytes when it goes to the verifier.
	AttestationTypeWeb2Json = "Web2Json"

	// SourceIDPublicWeb2 is the data source identifier for public Web2 APIs.
	SourceIDPublicWeb2 = "PublicWeb2"

	// DefaultVerifierURL is Flare's rate-limited testnet verifier. Production
	// deployments are expected to run their own.
	DefaultVerifierURL = "https://fdc-verifiers-testnet.flare.network"

	// DefaultDALayerURL is Flare's public Coston2 Data Availability Layer.
	DefaultDALayerURL = "https://ctn2-data-availability.flare.network"

	// DefaultAPIKey is the open testnet key both services accept; it is published
	// in Flare's own starter repositories and grants nothing but rate-limited
	// access to public testnet data.
	DefaultAPIKey = "00000000-0000-0000-0000-000000000000"
)

// Client talks to the off-chain half of the FDC: the verifier that encodes
// requests and the DA Layer that serves proofs.
type Client struct {
	VerifierURL string
	DALayerURL  string
	APIKey      string
	HTTP        *http.Client
}

// NewClient returns a client pointed at Flare's public testnet services, with
// every endpoint overridable from the environment so a self-hosted verifier or
// DA Layer can be dropped in without code changes.
func NewClient() *Client {
	return &Client{
		VerifierURL: envOr("FDC_VERIFIER_URL", DefaultVerifierURL),
		DALayerURL:  envOr("FDC_DA_LAYER_URL", DefaultDALayerURL),
		APIKey:      envOr("FDC_API_KEY", DefaultAPIKey),
		HTTP:        &http.Client{Timeout: 60 * time.Second},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// prepareRequestPayload is the JSON body the verifier expects. The request body
// is carried as sign.IWeb2JsonRequestBody so that the value sent to the verifier
// and the value hashed by InstructionSender.registerPolicyTrigger are literally
// the same struct — they must describe the same request or the on-chain binding
// check fails.
type prepareRequestPayload struct {
	AttestationType string             `json:"attestationType"`
	SourceID        string             `json:"sourceId"`
	RequestBody     requestBodyPayload `json:"requestBody"`
}

// requestBodyPayload mirrors IWeb2Json.RequestBody with the field names the
// verifier's JSON API uses.
type requestBodyPayload struct {
	URL           string `json:"url"`
	HTTPMethod    string `json:"httpMethod"`
	Headers       string `json:"headers"`
	QueryParams   string `json:"queryParams"`
	Body          string `json:"body"`
	PostProcessJq string `json:"postProcessJq"`
	AbiSignature  string `json:"abiSignature"`
}

func toPayload(rb sign.IWeb2JsonRequestBody) requestBodyPayload {
	return requestBodyPayload{
		URL:           rb.Url,
		HTTPMethod:    rb.HttpMethod,
		Headers:       rb.Headers,
		QueryParams:   rb.QueryParams,
		Body:          rb.Body,
		PostProcessJq: rb.PostProcessJq,
		AbiSignature:  rb.AbiSignature,
	}
}

// EncodeAttestationName UTF-8 hex encodes an attestation type or source id and
// zero-pads it to 32 bytes, the form the verifier expects.
func EncodeAttestationName(name string) (string, error) {
	if len(name) > 32 {
		return "", errors.Errorf("attestation name %q exceeds 32 bytes", name)
	}
	padded := make([]byte, 32)
	copy(padded, name)

	return "0x" + hex.EncodeToString(padded), nil
}

type prepareRequestResponse struct {
	Status            string `json:"status"`
	ABIEncodedRequest string `json:"abiEncodedRequest"`
}

// PrepareRequest asks the verifier to validate and encode a Web2Json request.
//
// A non-VALID status means the verifier could not produce a response for this
// request — usually a jq filter it cannot evaluate, or output that does not match
// abiSignature. The returned bytes are what FdcHub is given and what the DA Layer
// is later asked about, so they must be kept for step 4.
func (c *Client) PrepareRequest(ctx context.Context, requestBody sign.IWeb2JsonRequestBody) ([]byte, error) {
	attestationType, err := EncodeAttestationName(AttestationTypeWeb2Json)
	if err != nil {
		return nil, err
	}
	sourceID, err := EncodeAttestationName(SourceIDPublicWeb2)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(prepareRequestPayload{
		AttestationType: attestationType,
		SourceID:        sourceID,
		RequestBody:     toPayload(requestBody),
	})
	if err != nil {
		return nil, errors.Errorf("encoding prepareRequest payload: %s", err)
	}

	url := strings.TrimSuffix(c.VerifierURL, "/") + "/verifier/web2/Web2Json/prepareRequest"
	body, err := c.post(ctx, url, payload)
	if err != nil {
		return nil, err
	}

	var parsed prepareRequestResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.Errorf("decoding prepareRequest response: %s", err)
	}
	if parsed.Status != "VALID" {
		return nil, errors.Errorf("verifier rejected the request: %s", parsed.Status)
	}

	encoded, err := hexutilDecode(parsed.ABIEncodedRequest)
	if err != nil {
		return nil, errors.Errorf("decoding abiEncodedRequest: %s", err)
	}

	return encoded, nil
}

// daProofResponse is the DA Layer's raw proof envelope.
type daProofResponse struct {
	AttestationType string   `json:"attestation_type"`
	Proof           []string `json:"proof"`
	ResponseHex     string   `json:"response_hex"`
}

// FetchProof asks the DA Layer for the attested response and Merkle proof of one
// request in one voting round. It returns a nil proof and a nil error while the
// round has not been finalized yet, so callers can poll without treating "not
// ready" as a failure.
func (c *Client) FetchProof(
	ctx context.Context,
	votingRoundID uint64,
	abiEncodedRequest []byte,
) (*sign.IWeb2JsonProof, error) {
	payload, err := json.Marshal(map[string]any{
		"votingRoundId": votingRoundID,
		"requestBytes":  "0x" + hex.EncodeToString(abiEncodedRequest),
	})
	if err != nil {
		return nil, errors.Errorf("encoding proof request: %s", err)
	}

	url := strings.TrimSuffix(c.DALayerURL, "/") + "/api/v1/fdc/proof-by-request-round-raw"
	body, err := c.post(ctx, url, payload)
	if err != nil {
		// The DA Layer answers 400 "attestation request not found" both for a
		// round that is still open and for a request it never saw. Only the
		// caller's timeout can tell the two apart.
		if strings.Contains(err.Error(), "attestation request not found") {
			return nil, nil
		}
		return nil, err
	}

	var parsed daProofResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.Errorf("decoding proof response: %s", err)
	}
	if parsed.ResponseHex == "" {
		return nil, nil
	}

	return DecodeProof(parsed.Proof, parsed.ResponseHex)
}

// WaitForProof polls FetchProof until the round is finalized or the context is done.
func (c *Client) WaitForProof(
	ctx context.Context,
	votingRoundID uint64,
	abiEncodedRequest []byte,
	pollInterval time.Duration,
) (*sign.IWeb2JsonProof, error) {
	for {
		proof, err := c.FetchProof(ctx, votingRoundID, abiEncodedRequest)
		if err != nil {
			return nil, err
		}
		if proof != nil {
			return proof, nil
		}

		select {
		case <-ctx.Done():
			return nil, errors.Errorf(
				"no proof for voting round %d within the timeout — the round may not have been finalized",
				votingRoundID)
		case <-time.After(pollInterval):
		}
	}
}

func (c *Client) post(ctx context.Context, url string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Errorf("building request for %s: %s", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, errors.Errorf("calling %s: %s", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.Errorf("reading response from %s: %s", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("%s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

// DecodeProof turns the DA Layer's hex blobs into the struct the contract takes.
//
// responseHex is the ABI encoding of IWeb2Json.Response; it is decoded through the
// contract's own ABI rather than a hand-written type, so the layout can never
// drift from what FdcVerification hashes.
func DecodeProof(merkleProof []string, responseHex string) (*sign.IWeb2JsonProof, error) {
	responseBytes, err := hexutilDecode(responseHex)
	if err != nil {
		return nil, errors.Errorf("decoding response_hex: %s", err)
	}

	responseType, err := web2JsonResponseType()
	if err != nil {
		return nil, err
	}

	values, err := abi.Arguments{{Name: "data", Type: responseType}}.Unpack(responseBytes)
	if err != nil {
		return nil, errors.Errorf("ABI-decoding attestation response: %s", err)
	}
	if len(values) != 1 {
		return nil, errors.Errorf("expected 1 value in attestation response, got %d", len(values))
	}

	response := *abi.ConvertType(values[0], new(sign.IWeb2JsonResponse)).(*sign.IWeb2JsonResponse)

	nodes := make([][32]byte, 0, len(merkleProof))
	for i, node := range merkleProof {
		raw, err := hexutilDecode(node)
		if err != nil {
			return nil, errors.Errorf("decoding merkle proof node %d: %s", i, err)
		}
		if len(raw) != 32 {
			return nil, errors.Errorf("merkle proof node %d is %d bytes, want 32", i, len(raw))
		}
		nodes = append(nodes, [32]byte(raw))
	}

	return &sign.IWeb2JsonProof{MerkleProof: nodes, Data: response}, nil
}

// web2JsonResponseType pulls the IWeb2Json.Response tuple type out of the
// InstructionSender ABI (it is the `data` member of the proof `evaluate` takes).
func web2JsonResponseType() (abi.Type, error) {
	parsed, err := sign.InstructionSenderMetaData.GetAbi()
	if err != nil {
		return abi.Type{}, errors.Errorf("loading InstructionSender ABI: %s", err)
	}

	method, ok := parsed.Methods["evaluate"]
	if !ok {
		return abi.Type{}, errors.New("InstructionSender ABI has no evaluate method")
	}
	for _, input := range method.Inputs {
		if input.Type.T != abi.TupleTy {
			continue
		}
		for i, name := range input.Type.TupleRawNames {
			if name == "data" {
				return *input.Type.TupleElems[i], nil
			}
		}
	}

	return abi.Type{}, errors.New("evaluate has no Web2Json proof parameter")
}

// DecodeWeatherReading unpacks the jq-filtered payload the attestation carries.
func DecodeWeatherReading(proof *sign.IWeb2JsonProof) (*sign.InstructionSenderWeatherReading, error) {
	if proof == nil {
		return nil, errors.New("proof is nil")
	}

	parsed, err := sign.InstructionSenderMetaData.GetAbi()
	if err != nil {
		return nil, errors.Errorf("loading InstructionSender ABI: %s", err)
	}
	method, ok := parsed.Methods["weatherReadingAbi"]
	if !ok || len(method.Inputs) != 1 {
		return nil, errors.New("InstructionSender ABI does not expose WeatherReading")
	}

	values, err := abi.Arguments{method.Inputs[0]}.Unpack(proof.Data.ResponseBody.AbiEncodedData)
	if err != nil {
		return nil, errors.Errorf("ABI-decoding weather reading: %s", err)
	}
	if len(values) != 1 {
		return nil, errors.Errorf("expected 1 weather reading, got %d", len(values))
	}

	return abi.ConvertType(values[0], new(sign.InstructionSenderWeatherReading)).(*sign.InstructionSenderWeatherReading), nil
}

// requestFeeABI is the one method Aegis needs from IFdcRequestFeeConfigurations.
// Copied from flare-smart-contracts-v2/contracts/userInterfaces/IFdcRequestFeeConfigurations.sol.
const requestFeeABI = `[{"inputs":[{"internalType":"bytes","name":"_data","type":"bytes"}],` +
	`"name":"getRequestFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],` +
	`"stateMutability":"view","type":"function"}]`

// RequestFee reads the fee FdcHub charges for one attestation request. The fee is
// per attestation type and set by governance, so it is always read, never assumed.
func RequestFee(s *support.Support, abiEncodedRequest []byte) (*big.Int, error) {
	if s.FdcHub == nil {
		return nil, errors.New("FdcHub address is not configured — check the deployed addresses file")
	}

	feeConfig, err := s.FdcHub.FdcRequestFeeConfigurations(&bind.CallOpts{})
	if err != nil {
		return nil, errors.Errorf("reading fdcRequestFeeConfigurations: %s", err)
	}

	parsed, err := abi.JSON(strings.NewReader(requestFeeABI))
	if err != nil {
		return nil, errors.Errorf("parsing request fee ABI: %s", err)
	}

	contract := bind.NewBoundContract(feeConfig, parsed, s.ChainClient, nil, nil)

	var out []any
	if err := contract.Call(&bind.CallOpts{}, &out, "getRequestFee", abiEncodedRequest); err != nil {
		return nil, errors.Errorf("calling getRequestFee: %s", err)
	}
	if len(out) != 1 {
		return nil, errors.Errorf("getRequestFee returned %d values, want 1", len(out))
	}

	fee, ok := out[0].(*big.Int)
	if !ok {
		return nil, errors.Errorf("getRequestFee returned %T, want uint256", out[0])
	}

	return fee, nil
}

// SubmitRequest sends an attestation request to FdcHub and returns the voting
// round it landed in, together with the transaction hash.
//
// The round is derived from the timestamp of the block that mined the request:
// FDC assigns every request to the voting epoch its submission block falls in.
func SubmitRequest(s *support.Support, abiEncodedRequest []byte) (uint64, common.Hash, error) {
	if s.FdcHub == nil {
		return 0, common.Hash{}, errors.New("FdcHub address is not configured — check the deployed addresses file")
	}

	fee, err := RequestFee(s, abiEncodedRequest)
	if err != nil {
		return 0, common.Hash{}, err
	}

	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return 0, common.Hash{}, errors.Errorf("creating transactor: %s", err)
	}
	opts.Value = fee

	tx, err := s.FdcHub.RequestAttestation(opts, abiEncodedRequest)
	if err != nil {
		return 0, common.Hash{}, errors.Errorf("requestAttestation: %s", err)
	}

	receipt, err := support.CheckTx(tx, s.ChainClient)
	if err != nil {
		return 0, common.Hash{}, errors.Errorf("requestAttestation: %s", err)
	}

	header, err := s.ChainClient.HeaderByHash(context.Background(), receipt.BlockHash)
	if err != nil {
		return 0, common.Hash{}, errors.Errorf("reading submission block: %s", err)
	}

	round, err := VotingRoundID(s, header.Time)
	if err != nil {
		return 0, common.Hash{}, err
	}

	return round, receipt.TxHash, nil
}

// VotingRoundID converts a unix timestamp into the FDC voting round covering it,
// using the epoch geometry FlareSystemsManager publishes.
func VotingRoundID(s *support.Support, timestamp uint64) (uint64, error) {
	first, err := s.FlareSystemManager.FirstVotingRoundStartTs(&bind.CallOpts{})
	if err != nil {
		return 0, errors.Errorf("reading firstVotingRoundStartTs: %s", err)
	}
	duration, err := s.FlareSystemManager.VotingEpochDurationSeconds(&bind.CallOpts{})
	if err != nil {
		return 0, errors.Errorf("reading votingEpochDurationSeconds: %s", err)
	}
	if duration == 0 {
		return 0, errors.New("votingEpochDurationSeconds is zero")
	}
	if timestamp < first {
		return 0, errors.Errorf("timestamp %d precedes the first voting round", timestamp)
	}

	return (timestamp - first) / duration, nil
}

// hexutilDecode accepts hex with or without the 0x prefix.
func hexutilDecode(s string) ([]byte, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(s), "0x")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	return decoded, nil
}
