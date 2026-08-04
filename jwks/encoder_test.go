package jwks_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/internal/testkeys"
	"github.com/veles-security/voauth/jwk"
	"github.com/veles-security/voauth/jwks"
)

func TestEncoder_Encode(t *testing.T) {
	decoder, err := jwks.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder() failed: %v", err)
	}
	assertDecoded := func(t *testing.T, artifact *jwks.Jwks, got []byte, err error) {
		if err != nil {
			t.Fatalf("Encode() failed: %v", err)
		}
		decoded, err := decoder.Decode(context.Background(), got)
		if err != nil {
			t.Fatalf("Decode() failed: %v", err)
		}
		if !reflect.DeepEqual(decoded, artifact) {
			t.Errorf("decoded JWKS = %#v, want %#v", decoded, artifact)
		}
	}
	assertMalformed := func(t *testing.T, artifact *jwks.Jwks, got []byte, err error) {
		if err == nil {
			t.Fatalf("Decode() failed: want %#v got nil", vapi.ErrMalformed)
		}
		if !errors.Is(err, vapi.ErrMalformed) {
			t.Fatalf("Decode() failed: want %#v got %#v", vapi.ErrMalformed, err)
		}
	}
	tests := []struct {
		name          string
		configOptions []jwks.EncoderConfigOption
		artifact      *jwks.Jwks
		assert        func(t *testing.T, artifact *jwks.Jwks, got []byte, err error)
	}{
		{
			name: "RSA key with RS256",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS256,
				testkeys.Public(t, testkeys.RSA2048),
				"rsa-key",
			)}},
			assert: assertDecoded,
		},
		{
			name:     "RSA key with RS256 and nil artifacr",
			artifact: nil,
			assert:   assertMalformed,
		},
		{
			name: "RSA key with malformed RS256",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS256,
				testkeys.MalformedPublic(t, testkeys.RSA2048, testkeys.IncompleteKey),
				"rsa-key",
			)}},
			assert: assertMalformed,
		},
		{
			name: "RSA key with RS384",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS384,
				testkeys.Public(t, testkeys.RSA2048),
				"rsa-key",
			)}},
			assert: assertDecoded,
		},
		{
			name: "ECDSA key with keyES256",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES256,
				testkeys.Public(t, testkeys.RSA2048),
				"ecdsa-key",
			)}},
			assert: assertDecoded,
		},
		{
			name: "ECDSA key with ES384",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES384,
				testkeys.Public(t, testkeys.ES384),
				"ecdsa-key",
			)}},
			assert: assertDecoded,
		},
		{
			name: "ECDSA key with ES512",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES512,
				testkeys.Public(t, testkeys.ES512),
				"ecdsa-key",
			)}},
			assert: assertDecoded,
		},
		{
			name: "Ed25519 key with EdDSA",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgEd25519,
				testkeys.Public(t, testkeys.Ed25519),
				"ed25519-key",
			)}},
			assert: assertDecoded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := jwks.NewEncoder(tt.configOptions...)
			if err != nil {
				t.Fatalf("NewEncoder() failed: %v", err)
			}
			got, err := encoded.Encode(context.Background(), tt.artifact)
			tt.assert(t, tt.artifact, got, err)
		})
	}
}

func TestNewEncoder(t *testing.T) {
	assertEncoderCreated := func(t *testing.T, got *jwks.Encoder, err error) {
		if got == nil {
			t.Fatalf("NewEncoder() failed: got nil Encoder")
		}
		if err != nil {
			t.Fatalf("NewEncoder() failed: %#v", err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *jwks.Encoder, err error) {
		if err == nil {
			t.Fatalf("NewEncoder() failed: want %#v got nil", vapi.ErrMisconfigured)
		}
		if !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewEncoder() failed: want %#v got %#v", vapi.ErrMisconfigured, err)
		}
	}

	tests := []struct {
		name          string // description of this test case
		configOptions []jwks.EncoderConfigOption
		assert        func(t *testing.T, got *jwks.Encoder, err error)
	}{
		{
			name:   "default",
			assert: assertEncoderCreated,
		},
		{
			name: "nil option",
			configOptions: []jwks.EncoderConfigOption{
				nil,
			},
			assert: assertMisconfigured,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := jwks.NewEncoder(tt.configOptions...)
			tt.assert(t, got, gotErr)
		})
	}
}
