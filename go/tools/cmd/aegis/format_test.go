package main

import (
	"math/big"
	"strings"
	"testing"
)

func TestFormatTenths(t *testing.T) {
	cases := map[string]string{
		"1167":  "116.7",
		"10810": "1081.0",
		"0":     "0.0",
		"5":     "0.5",
	}

	for input, want := range cases {
		value, ok := new(big.Int).SetString(input, 10)
		if !ok {
			t.Fatalf("bad test input %q", input)
		}
		if got := formatTenths(value); got != want {
			t.Errorf("formatTenths(%s) = %s, want %s", input, got, want)
		}
	}
}

// The coordinates in an attestation are signed microdegrees, and the southern
// hemisphere is the case a naive formatter gets wrong.
func TestFormatMicroDegrees(t *testing.T) {
	cases := map[string]string{
		"-7275922":  "-7.275922",
		"112785774": "112.785774",
		"0":         "0.000000",
		"-500":      "-0.000500",
	}

	for input, want := range cases {
		value, ok := new(big.Int).SetString(input, 10)
		if !ok {
			t.Fatalf("bad test input %q", input)
		}
		if got := formatMicroDegrees(value); got != want {
			t.Errorf("formatMicroDegrees(%s) = %s, want %s", input, got, want)
		}
	}
}

// assertSealed is the last guard before a model leaves the process, so it has to
// catch a parameter that survived encryption. The failure it protects against is
// silent by nature: a leaked ciphertext looks fine until someone reads it.
func TestAssertSealedRejectsLeakedParameter(t *testing.T) {
	model := demoModel()

	if err := assertSealed(model, []byte("this ciphertext carries 9000 in the clear")); err == nil {
		t.Error("assertSealed accepted a payload containing a parameter")
	}

	if err := assertSealed(model, []byte("opaque bytes with no parameter in them")); err != nil {
		t.Errorf("assertSealed rejected a clean payload: %s", err)
	}
}

// An error message must not name a parameter either, or the guard would leak
// what it exists to protect.
func TestAssertSealedErrorNamesNoParameter(t *testing.T) {
	model := demoModel()

	err := assertSealed(model, []byte("leaked 1200 here"))
	if err == nil {
		t.Fatal("expected an error")
	}

	for _, secret := range secretStrings(model) {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error message contains a model parameter")
		}
	}
}

func TestNewPolicyIDCarriesPrefix(t *testing.T) {
	id, err := newPolicyID(0xa3d1)
	if err != nil {
		t.Fatalf("newPolicyID: %s", err)
	}

	if id[0] != 0xa3 || id[1] != 0xd1 {
		t.Errorf("policy id %s does not start with the requested prefix", id.Hex())
	}

	other, err := newPolicyID(0xa3d1)
	if err != nil {
		t.Fatalf("newPolicyID: %s", err)
	}
	if id == other {
		t.Error("two policy ids from the same prefix collided, so ids are not run unique")
	}
}
