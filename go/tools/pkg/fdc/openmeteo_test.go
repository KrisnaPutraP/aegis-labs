package fdc

import (
	"encoding/json"
	"strings"
	"testing"
)

func testFeed() DroughtFeed {
	return DroughtFeed{
		LatitudeDeg:  "-7.25",
		LongitudeDeg: "112.75",
		StartDate:    "2025-06-01",
		EndDate:      "2025-08-31",
	}
}

func TestRequestBodyIsReproducible(t *testing.T) {
	// The request body is hashed into the policy's on-chain trigger, so the same
	// feed must always produce byte-identical bytes — otherwise a policy could
	// stop being settleable by its own feed.
	first, err := testFeed().RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}
	second, err := testFeed().RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}

	if first != second {
		t.Errorf("same feed produced different request bodies:\n%+v\n%+v", first, second)
	}
}

func TestRequestBodyCarriesTheFeed(t *testing.T) {
	body, err := testFeed().RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}

	if body.Url != OpenMeteoArchiveURL {
		t.Errorf("url = %q, want %q", body.Url, OpenMeteoArchiveURL)
	}
	if body.HttpMethod != "GET" {
		t.Errorf("httpMethod = %q, want GET", body.HttpMethod)
	}

	var params map[string]string
	if err := json.Unmarshal([]byte(body.QueryParams), &params); err != nil {
		t.Fatalf("query params are not valid JSON: %v", err)
	}
	for key, want := range map[string]string{
		"latitude":   "-7.25",
		"longitude":  "112.75",
		"start_date": "2025-06-01",
		"end_date":   "2025-08-31",
		"daily":      "precipitation_sum",
		"timezone":   "UTC",
	} {
		if params[key] != want {
			t.Errorf("query param %s = %q, want %q", key, params[key], want)
		}
	}
}

func TestDifferentWindowsProduceDifferentRequests(t *testing.T) {
	// Two policies over the same location must not share a request body: if they
	// did, one policy's attestation would settle the other.
	dry, err := testFeed().RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}

	wetFeed := testFeed()
	wetFeed.StartDate = "2024-12-01"
	wetFeed.EndDate = "2025-02-28"
	wet, err := wetFeed.RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}

	if dry.QueryParams == wet.QueryParams {
		t.Error("dry and wet season windows encode to the same query")
	}
}

func TestJqOutputMatchesTheAbiSignature(t *testing.T) {
	// The verifier maps jq output keys onto the ABI signature's components by
	// name, and the component order has to match InstructionSender.WeatherReading.
	// A rename on one side only would be caught here rather than by a failing
	// attestation three minutes into an end-to-end run.
	body, err := testFeed().RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}

	var signature struct {
		Components []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"components"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(body.AbiSignature), &signature); err != nil {
		t.Fatalf("abi signature is not valid JSON: %v", err)
	}

	want := []struct{ name, typ string }{
		{"latitudeMicroDeg", "int256"},
		{"longitudeMicroDeg", "int256"},
		{"rainfallTenthsMm", "uint256"},
	}
	if len(signature.Components) != len(want) {
		t.Fatalf("abi signature has %d components, want %d", len(signature.Components), len(want))
	}
	for i, w := range want {
		if signature.Components[i].Name != w.name || signature.Components[i].Type != w.typ {
			t.Errorf("component %d = %s %s, want %s %s",
				i, signature.Components[i].Type, signature.Components[i].Name, w.typ, w.name)
		}
		if !strings.Contains(body.PostProcessJq, w.name+":") {
			t.Errorf("jq filter does not produce %q", w.name)
		}
	}
}

func TestJqFilterAvoidsUnsupportedBuiltins(t *testing.T) {
	// Flare's Web2Json verifier rejects filters using jq's math builtins; the
	// filter truncates through tostring/split instead. Guard the workaround so a
	// future edit does not quietly reintroduce them.
	body, err := testFeed().RequestBody()
	if err != nil {
		t.Fatalf("RequestBody: %v", err)
	}

	for _, builtin := range []string{"floor", "round", "ceil"} {
		if strings.Contains(body.PostProcessJq, builtin) {
			t.Errorf("jq filter uses %q, which the verifier rejects", builtin)
		}
	}
	if !strings.Contains(body.PostProcessJq, `split(".")`) {
		t.Error("jq filter no longer truncates via split(\".\")")
	}
}

func TestValidateRejectsIncompleteFeeds(t *testing.T) {
	cases := map[string]func(*DroughtFeed){
		"latitude":  func(f *DroughtFeed) { f.LatitudeDeg = "" },
		"longitude": func(f *DroughtFeed) { f.LongitudeDeg = "" },
		"start":     func(f *DroughtFeed) { f.StartDate = "" },
		"end":       func(f *DroughtFeed) { f.EndDate = "" },
	}

	for name, blank := range cases {
		t.Run(name, func(t *testing.T) {
			feed := testFeed()
			blank(&feed)

			if err := feed.Validate(); err == nil {
				t.Error("expected an error for an incomplete feed")
			}
			if _, err := feed.RequestBody(); err == nil {
				t.Error("expected RequestBody to refuse an incomplete feed")
			}
		})
	}
}
