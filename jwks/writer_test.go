package jwks_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/internal/testkeys"
	"github.com/veles-security/voauth/jwk"
	"github.com/veles-security/voauth/jwks"
)

func TestWriter_WriteArtifact(t *testing.T) {
	decoder, err := jwks.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder() failed: %v", err)
	}
	assertWritten := func(t *testing.T, artifact *jwks.Jwks, got http.ResponseWriter, err error) {
		if err != nil {
			t.Fatalf("WriteArtifact() failed: %v", err)
		}
		response := got.(*httptest.ResponseRecorder).Result()
		if response.StatusCode != http.StatusOK {
			t.Errorf("status code = %d, want %d", response.StatusCode, http.StatusOK)
		}
		if contentType := response.Header.Get("Content-Type"); contentType != "application/jwk-set+json" {
			t.Errorf("Content-Type = %q, want %q", contentType, "application/jwk-set+json")
		}
		if contentTypeOptions := response.Header.Get("X-Content-Type-Options"); contentTypeOptions != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want %q", contentTypeOptions, "nosniff")
		}
		decoded, decodeErr := decoder.Decode(context.Background(), got.(*httptest.ResponseRecorder).Body.Bytes())
		if decodeErr != nil {
			t.Fatalf("Decode() failed: %v", decodeErr)
		}
		if !reflect.DeepEqual(decoded, artifact) {
			t.Errorf("decoded JWKS = %#v, want %#v", decoded, artifact)
		}
	}
	assertMalformed := func(t *testing.T, artifact *jwks.Jwks, got http.ResponseWriter, err error) {
		if err == nil {
			t.Fatalf("WriteArtifact() failed: want %#v got nil", vapi.ErrMalformed)
		}
		if !errors.Is(err, vapi.ErrMalformed) {
			t.Fatalf("WriteArtifact() failed: want %#v got %#v", vapi.ErrMalformed, err)
		}
	}
	tests := []struct {
		name          string // description of this test case
		configOptions []jwks.WriterConfigOption
		carrierWriter http.ResponseWriter
		artifact      *jwks.Jwks
		options       []jwks.WriterOption
		assert        func(t *testing.T, artifact *jwks.Jwks, got http.ResponseWriter, err error)
	}{
		{
			name:          "RSA key with RS256",
			carrierWriter: httptest.NewRecorder(),
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS256,
				testkeys.Public(t, testkeys.RSA2048),
				"rsa-key",
			)}},
			assert: assertWritten,
		},
		{
			name:          "RSA key with nil Keys",
			carrierWriter: httptest.NewRecorder(),
			artifact:      &jwks.Jwks{Keys: nil},
			assert:        assertMalformed,
		},
		{
			name:          "RSA key with 0 Keys",
			carrierWriter: httptest.NewRecorder(),
			artifact:      &jwks.Jwks{Keys: make([]jwk.Jwk, 0)},
			assert:        assertMalformed,
		},
		{
			name:          "nil Jwk Key",
			carrierWriter: httptest.NewRecorder(),
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{{SignVerifier: sig.SignVerifier{
				Alg: sig.SigAlgRS256,
				Key: nil,
				Kid: "rsa-key",
			}}}},
			assert: assertMalformed,
		},
		{
			name:          "RSA key with RS384",
			carrierWriter: httptest.NewRecorder(),
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS384,
				testkeys.Public(t, testkeys.RSA2048),
				"rsa-key",
			)}},
			assert: assertWritten,
		},
		{
			name:          "ECDSA key with ES384",
			carrierWriter: httptest.NewRecorder(),
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES384,
				testkeys.Public(t, testkeys.ES384),
				"ecdsa-key",
			)}},
			assert: assertWritten,
		},
		{
			name:          "ECDSA key with ES512",
			carrierWriter: httptest.NewRecorder(),
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES512,
				testkeys.Public(t, testkeys.ES512),
				"ecdsa-key",
			)}},
			assert: assertWritten,
		},
		{
			name:          "Ed25519 key with EdDSA",
			carrierWriter: httptest.NewRecorder(),
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgEd25519,
				testkeys.Public(t, testkeys.Ed25519),
				"ed25519-key",
			)}},
			assert: assertWritten,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := jwks.NewWriter(tt.configOptions...)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			gotErr := w.WriteArtifact(context.Background(), tt.carrierWriter, tt.artifact, tt.options...)
			tt.assert(t, tt.artifact, tt.carrierWriter, gotErr)
		})
	}
}
