package fdc

import (
	"encoding/json"
	"fmt"

	"sign-extension/tools/pkg/contracts/sign"

	"github.com/pkg/errors"
)

// The public weather feed an Aegis drought policy is settled on.
//
// Open-Meteo's archive endpoint is used rather than a forecast one on purpose: a
// policy settles on what already happened over a closed window, so the same
// request keeps returning the same reading forever. That is what makes an
// attestation reproducible — and what lets a policy's trigger be pinned to a
// single request body at underwriting time.
const (
	// OpenMeteoArchiveURL serves daily historical weather. No API key, no auth.
	OpenMeteoArchiveURL = "https://archive-api.open-meteo.com/v1/archive"

	// weatherReadingABISignature tells the verifier how to encode the jq output.
	// The field order must match InstructionSender.WeatherReading, and the names
	// must match the keys the jq filter produces.
	weatherReadingABISignature = `{"components":[` +
		`{"internalType":"int256","name":"latitudeMicroDeg","type":"int256"},` +
		`{"internalType":"int256","name":"longitudeMicroDeg","type":"int256"},` +
		`{"internalType":"uint256","name":"rainfallTenthsMm","type":"uint256"}],` +
		`"name":"reading","type":"tuple"}`

	// rainfallJq reduces Open-Meteo's daily series to one integer.
	//
	// Two constraints shape this filter. Solidity has no floats, so degrees are
	// scaled to micro-degrees and millimetres to tenths, then truncated. And the
	// verifier's jq has no math builtins — `floor` and `round` are both rejected —
	// so truncation is done by rendering the number and cutting at the decimal
	// point. Prepending 0 to the series keeps `add` defined when a window has no
	// readings at all, which would otherwise yield null and fail ABI encoding.
	rainfallJq = `{latitudeMicroDeg: (.latitude*1000000|tostring|split(".")|.[0]|tonumber), ` +
		`longitudeMicroDeg: (.longitude*1000000|tostring|split(".")|.[0]|tonumber), ` +
		`rainfallTenthsMm: ([0]+(.daily.precipitation_sum|map(select(.!=null)))|add*10|tostring|split(".")|.[0]|tonumber)}`
)

// DroughtFeed identifies the rainfall series one policy is underwritten against:
// a location and a closed date window.
type DroughtFeed struct {
	// LatitudeDeg and LongitudeDeg are decimal degrees as they appear in the
	// query string, e.g. "-7.25". Kept as strings so the request body is
	// byte-reproducible — a float formatted twice is a hash mismatch waiting to
	// happen.
	LatitudeDeg  string
	LongitudeDeg string

	// StartDate and EndDate bound the coverage window, "YYYY-MM-DD" inclusive.
	StartDate string
	EndDate   string
}

// Validate reports whether the feed is fully specified. It does not check that
// the dates exist or that the window is in the past — Open-Meteo and the verifier
// do that, and a request they reject never becomes an attestation.
func (f DroughtFeed) Validate() error {
	switch {
	case f.LatitudeDeg == "":
		return errors.New("drought feed: latitude is empty")
	case f.LongitudeDeg == "":
		return errors.New("drought feed: longitude is empty")
	case f.StartDate == "":
		return errors.New("drought feed: start date is empty")
	case f.EndDate == "":
		return errors.New("drought feed: end date is empty")
	}

	return nil
}

// queryParams renders the Open-Meteo query as the stringified JSON the Web2Json
// request body carries. Field order is fixed by the struct, so the same feed
// always produces the same bytes and therefore the same trigger hash.
func (f DroughtFeed) queryParams() (string, error) {
	params := struct {
		Latitude  string `json:"latitude"`
		Longitude string `json:"longitude"`
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
		Daily     string `json:"daily"`
		Timezone  string `json:"timezone"`
	}{
		Latitude:  f.LatitudeDeg,
		Longitude: f.LongitudeDeg,
		StartDate: f.StartDate,
		EndDate:   f.EndDate,
		Daily:     "precipitation_sum",
		Timezone:  "UTC",
	}

	encoded, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("encoding query params: %w", err)
	}

	return string(encoded), nil
}

// RequestBody builds the Web2Json request body for this feed.
//
// The very same value is sent to the verifier and hashed into the policy's
// on-chain trigger, so an attestation of any other location, window, filter or
// output shape can never settle the policy.
func (f DroughtFeed) RequestBody() (sign.IWeb2JsonRequestBody, error) {
	if err := f.Validate(); err != nil {
		return sign.IWeb2JsonRequestBody{}, err
	}

	queryParams, err := f.queryParams()
	if err != nil {
		return sign.IWeb2JsonRequestBody{}, err
	}

	return sign.IWeb2JsonRequestBody{
		Url:           OpenMeteoArchiveURL,
		HttpMethod:    "GET",
		Headers:       "{}",
		QueryParams:   queryParams,
		Body:          "{}",
		PostProcessJq: rainfallJq,
		AbiSignature:  weatherReadingABISignature,
	}, nil
}
