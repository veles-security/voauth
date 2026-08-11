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
	var optionOrder []string
	decorate := func(name string) tokenrequest.WriterOption {
		return func(next tokenrequest.WriteFunc) tokenrequest.WriteFunc {
			return func(ctx context.Context, carrier *http.Request, artifact *tokenrequest.TokenRequest) error {
				optionOrder = append(optionOrder, name+" before")
				err := next(ctx, carrier, artifact)
				optionOrder = append(optionOrder, name+" after")
				return err
			}
		}
	}
	assertOptionsApplied := func(t *testing.T, artifact *tokenrequest.TokenRequest, got *http.Request, err error) {
		t.Helper()
		assertWritten(t, artifact, got, err)
		want := []string{"runtime before", "per-call before", "per-call after", "runtime after"}
		if !reflect.DeepEqual(optionOrder, want) {
			t.Errorf("writer option order = %#v, want %#v", optionOrder, want)
		}
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
			name:          "configured and per-call runtime options",
			configOptions: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterRuntimeOptions(decorate("runtime"))},
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType},
			options:       []tokenrequest.WriterOption{decorate("per-call")},
			assert:        assertOptionsApplied,
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
			name:          "nil configured writer option",
			configOptions: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterRuntimeOptions(nil)},
			carrierWriter: request(),
			artifact:      &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType},
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
			optionOrder = nil
			w, err := tokenrequest.NewWriter(tt.configOptions...)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			gotErr := w.WriteArtifact(context.Background(), tt.carrierWriter, tt.artifact, tt.options...)
			tt.assert(t, tt.artifact, tt.carrierWriter, gotErr)
		})
	}

	t.Run("nil receiver", func(t *testing.T) {
		var writer *tokenrequest.Writer
		err := writer.WriteArtifact(context.Background(), request(), &tokenrequest.TokenRequest{})
		assertError(vapi.ErrMisconfigured)(t, nil, nil, err)
	})
}

func TestNewWriter(t *testing.T) {
	assertCreated := func(t *testing.T, got *tokenrequest.Writer, err error) {
		t.Helper()
		if err != nil || got == nil {
			t.Fatalf("NewWriter() = (%#v, %v), want a writer and nil error", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *tokenrequest.Writer, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewWriter() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}

	tests := []struct {
		name    string
		options []tokenrequest.WriterConfigOption
		assert  func(*testing.T, *tokenrequest.Writer, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "dependency options", options: []tokenrequest.WriterConfigOption{
			tokenrequest.WithWriterTokenEncoderOptions(),
			tokenrequest.WithWriterAssertionTokenEncoderOptions(),
			tokenrequest.WithWriterClientCredentialsWriterOptions(),
		}, assert: assertCreated},
		{name: "nil config option", options: []tokenrequest.WriterConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil token encoder", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterTokenEncoder(nil)}, assert: assertMisconfigured},
		{name: "nil assertion token encoder", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterAssertionTokenEncoder(nil)}, assert: assertMisconfigured},
		{name: "nil client credentials writer", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterClientCredentialsWriter(nil)}, assert: assertMisconfigured},
		{name: "invalid token encoder options", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterTokenEncoderOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid assertion token encoder options", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterAssertionTokenEncoderOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid client credentials writer options", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterClientCredentialsWriterOptions(nil)}, assert: assertMisconfigured},
		{name: "nil configured runtime option", options: []tokenrequest.WriterConfigOption{tokenrequest.WithWriterRuntimeOptions(nil)}, assert: assertCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenrequest.NewWriter(tt.options...)
			tt.assert(t, got, err)
		})
	}
}
