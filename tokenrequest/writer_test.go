package tokenrequest_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/tokenrequest"
)

func TestWriter_WriteArtifact(t *testing.T) {
	reader, err := tokenrequest.NewReader()
	if err != nil {
		t.Fatalf("NewDecoder() failed: %v", err)
	}
	assertWritten := func(t *testing.T, artifact *tokenrequest.TokenRequest, got *http.Request, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("WriteArtifact() failed: %v", err)
		}
		if got.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want %q", got.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
		}
		if got.ContentLength <= 0 {
			t.Errorf("ContentLength = %d, want a positive value", got.ContentLength)
		}
		tokenRequest, err := reader.ReadArtifact(context.Background(), got)
		if err != nil {
			t.Fatalf("ReadArtifact() failed: %v", err)
		}
		if !reflect.DeepEqual(tokenRequest, artifact) {
			t.Errorf("TokenRequest = %#v, want %#v", tokenRequest, artifact)
		}
		if got.ContentLength != int64(len(got.PostForm.Encode())) {
			t.Errorf("ContentLength = %d, want %s", got.ContentLength, strconv.Itoa(len(got.PostForm.Encode())))
		}
	}
	assertError := func(category error) func(*testing.T, *tokenrequest.TokenRequest, *http.Request, error) {
		return func(t *testing.T, _ *tokenrequest.TokenRequest, _ *http.Request, err error) {
			t.Helper()
			if !errors.Is(err, category) {
				t.Fatalf("WriteArtifact() error = %v, want %v", err, category)
			}
		}
	}
	request := func() *http.Request {
		return &http.Request{Method: http.MethodPost, Header: make(http.Header)}
	}
	tests := []struct {
		name          string // description of this test case
		configOptions []tokenrequest.WriterConfigOption
		carrierWriter *http.Request
		artifact      *tokenrequest.TokenRequest
		options       []tokenrequest.WriterOption
		assert        func(t *testing.T, artifact *tokenrequest.TokenRequest, got *http.Request, err error)
	}{
		{
			name:          "authorization code",
			carrierWriter: request(),
			artifact: &tokenrequest.TokenRequest{GrantType: tokenrequest.AuthorizationCodeGrantType,
				Code: "code", RedirectUri: "https://client.example/callback", CodeVerifier: "verifier"},
			assert: assertWritten,
		},
		{
			name:          "password",
			carrierWriter: request(),
			artifact: &tokenrequest.TokenRequest{GrantType: tokenrequest.PasswordGrantType,
				Username: "user", Password: "secret", Scope: "read write"},
			assert: assertWritten,
		},
		{
			name:          "client credentials",
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType, Scope: "read"},
			assert:        assertWritten,
		},
		{
			name:          "device code",
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: tokenrequest.DeviceCodeGrantType, DeviceCode: "device-code"},
			assert:        assertWritten,
		},
		{
			name:          "unknown grant type",
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: "custom_grant"},
			assert:        assertWritten,
		},
		{
			name:     "nil request",
			artifact: &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType},
			assert:   assertError(vapi.ErrMalformed),
		},
		{
			name:          "nil artifact",
			carrierWriter: request(),
			assert:        assertError(vapi.ErrMalformed),
		},
		{
			name:          "nil writer option",
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType},
			options:       []tokenrequest.WriterOption{nil},
			assert:        assertError(vapi.ErrMisconfigured),
		},
		{
			name:          "writer option returns nil",
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType},
			options: []tokenrequest.WriterOption{
				func(tokenrequest.WriteFunc) tokenrequest.WriteFunc { return nil },
			},
			assert: assertError(vapi.ErrMisconfigured),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := tokenrequest.NewWriter(tt.configOptions...)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			gotErr := w.WriteArtifact(context.Background(), tt.carrierWriter, tt.artifact, tt.options...)
			tt.assert(t, tt.artifact, tt.carrierWriter, gotErr)
		})
	}
}
