package fdc

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

// proof_dry_season.json is a real Data Availability Layer response: the FDC's
// attestation of Open-Meteo rainfall over Surabaya's 2025 dry season, whose
// Merkle proof was verified against Coston2's FdcVerification contract when this
// fixture was captured. Decoding it offline pins the wire format the DA Layer
// serves and the ABI layout FdcVerification hashes.
const proofFixture = "testdata/proof_dry_season.json"

func loadFixture(t *testing.T) daProofResponse {
	t.Helper()

	raw, err := os.ReadFile(proofFixture)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var parsed daProofResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}

	return parsed
}

func TestDecodeProofReadsAttestedResponse(t *testing.T) {
	fixture := loadFixture(t)

	proof, err := DecodeProof(fixture.Proof, fixture.ResponseHex)
	if err != nil {
		t.Fatalf("DecodeProof: %v", err)
	}

	if got, want := len(proof.MerkleProof), len(fixture.Proof); got != want {
		t.Errorf("merkle proof has %d nodes, want %d", got, want)
	}
	if proof.Data.VotingRound == 0 {
		t.Error("voting round is zero")
	}
	if got, want := proof.Data.RequestBody.Url, OpenMeteoArchiveURL; got != want {
		t.Errorf("attested url = %q, want %q", got, want)
	}
	if !strings.Contains(proof.Data.RequestBody.PostProcessJq, "rainfallTenthsMm") {
		t.Errorf("attested jq filter does not produce rainfallTenthsMm: %q", proof.Data.RequestBody.PostProcessJq)
	}
}

func TestDecodeWeatherReadingMatchesTheAttestedWindow(t *testing.T) {
	fixture := loadFixture(t)

	proof, err := DecodeProof(fixture.Proof, fixture.ResponseHex)
	if err != nil {
		t.Fatalf("DecodeProof: %v", err)
	}

	reading, err := DecodeWeatherReading(proof)
	if err != nil {
		t.Fatalf("DecodeWeatherReading: %v", err)
	}

	// The fixture attests 116.7 mm over the dry-season window, reported at the
	// weather grid cell nearest Surabaya.
	if want := big.NewInt(1167); reading.RainfallTenthsMm.Cmp(want) != 0 {
		t.Errorf("rainfall = %s tenths of mm, want %s", reading.RainfallTenthsMm, want)
	}
	if reading.LatitudeMicroDeg.Sign() >= 0 {
		t.Errorf("latitude = %s, want a southern (negative) coordinate", reading.LatitudeMicroDeg)
	}
	if reading.LongitudeMicroDeg.Sign() <= 0 {
		t.Errorf("longitude = %s, want an eastern (positive) coordinate", reading.LongitudeMicroDeg)
	}
}

func TestDecodeProofRejectsMalformedInput(t *testing.T) {
	fixture := loadFixture(t)

	if _, err := DecodeProof(fixture.Proof, "0xnothex"); err == nil {
		t.Error("expected an error for a non-hex response")
	}
	if _, err := DecodeProof([]string{"0x1234"}, fixture.ResponseHex); err == nil {
		t.Error("expected an error for a merkle node that is not 32 bytes")
	}
	if _, err := DecodeProof(nil, "0x00"); err == nil {
		t.Error("expected an error for a response that is not an ABI-encoded attestation")
	}
}

func TestEncodeAttestationName(t *testing.T) {
	encoded, err := EncodeAttestationName(AttestationTypeWeb2Json)
	if err != nil {
		t.Fatalf("EncodeAttestationName: %v", err)
	}

	// "Web2Json" in UTF-8 hex, zero-padded to 32 bytes — the form Flare's verifier
	// and the on-chain attestation response both carry.
	const want = "0x576562324a736f6e000000000000000000000000000000000000000000000000"
	if encoded != want {
		t.Errorf("encoded = %s, want %s", encoded, want)
	}

	if _, err := EncodeAttestationName(strings.Repeat("x", 33)); err == nil {
		t.Error("expected an error for a name longer than 32 bytes")
	}
}

func TestNewClientPrefersEnvironmentOverrides(t *testing.T) {
	t.Setenv("FDC_VERIFIER_URL", "https://verifier.example")
	t.Setenv("FDC_DA_LAYER_URL", "https://da.example")
	t.Setenv("FDC_API_KEY", "test-key")

	client := NewClient()
	if client.VerifierURL != "https://verifier.example" ||
		client.DALayerURL != "https://da.example" ||
		client.APIKey != "test-key" {
		t.Errorf("environment overrides ignored: %+v", client)
	}
}
