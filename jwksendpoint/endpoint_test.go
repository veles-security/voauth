package jwksendpoint_test

import (
	"crypto"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/internal/testkeys"
	"github.com/veles-security/voauth/jwks"
	"github.com/veles-security/voauth/jwksendpoint"
)

func TestNew(t *testing.T) {
	signer := &sig.Signer{Key: testkeys.Private(t, testkeys.RSA2048).(crypto.Signer), Alg: sig.SigAlgRS256, Kid: "test-key"}
	assertCreated := func(t *testing.T, endpoint *jwksendpoint.JwksEndpoint, err error) {
		t.Helper()
		if err != nil || endpoint == nil {
			t.Fatalf("New() = (%#v, %v), want non-nil endpoint and nil error", endpoint, err)
		}
	}
	assertMisconfigured := func(t *testing.T, endpoint *jwksendpoint.JwksEndpoint, err error) {
		t.Helper()
		if endpoint != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("New() = (%#v, %v), want nil endpoint and %v", endpoint, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name       string
		options    []jwksendpoint.JwksEndpointConfigOption
		assertions func(*testing.T, *jwksendpoint.JwksEndpoint, error)
	}{
		{name: "creates endpoint", options: []jwksendpoint.JwksEndpointConfigOption{jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(signer))}, assertions: assertCreated},
		{name: "requires key", assertions: assertMisconfigured},
		{name: "rejects nil endpoint option", options: []jwksendpoint.JwksEndpointConfigOption{nil}, assertions: assertMisconfigured},
		{name: "rejects nil JWKS option", options: []jwksendpoint.JwksEndpointConfigOption{jwksendpoint.WithJwksOption(nil)}, assertions: assertMisconfigured},
		{name: "categorizes writer option failure", options: []jwksendpoint.JwksEndpointConfigOption{
			jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(signer)),
			jwksendpoint.WithJwksWriterOption(nil),
		}, assertions: assertMisconfigured},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := jwksendpoint.New(test.options...)
			test.assertions(t, endpoint, err)
		})
	}
}

func TestJwksEndpoint_ServeHTTP(t *testing.T) {
	signer := &sig.Signer{Key: testkeys.Private(t, testkeys.RSA2048).(crypto.Signer), Alg: sig.SigAlgRS256, Kid: "test-key"}
	endpoint, err := jwksendpoint.New(jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(signer)))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	assertJwks := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/jwk-set+json" {
			t.Fatalf("ServeHTTP() = status %d content type %q, want 200 application/jwk-set+json", response.Code, response.Header().Get("Content-Type"))
		}
		if response.Body.String() == "" {
			t.Fatal("ServeHTTP() returned an empty JWKS")
		}
	}
	assertMethodNotAllowed := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("ServeHTTP() = status %d Allow %q, want 405 Allow GET", response.Code, response.Header().Get("Allow"))
		}
	}
	tests := []struct {
		name       string
		method     string
		assertions func(*testing.T, *httptest.ResponseRecorder)
	}{
		{name: "serves JWKS", method: http.MethodGet, assertions: assertJwks},
		{name: "rejects unsupported method", method: http.MethodPost, assertions: assertMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, httptest.NewRequest(test.method, "/jwks", nil))
			test.assertions(t, response)
		})
	}
}
