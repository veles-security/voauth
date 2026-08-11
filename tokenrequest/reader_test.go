package tokenrequest_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/tokenrequest"
)

func TestReader_ReadArtifact(t *testing.T) {
	request := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials&scope=read"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return request
	}
	var optionOrder []string
	decorate := func(name string) tokenrequest.ReaderOption {
		return func(next tokenrequest.ReadFunc) tokenrequest.ReadFunc {
			return func(ctx context.Context, carrier *http.Request) (*tokenrequest.TokenRequest, error) {
				optionOrder = append(optionOrder, name+" before")
				artifact, err := next(ctx, carrier)
				optionOrder = append(optionOrder, name+" after")
				return artifact, err
			}
		}
	}
	assertRead := func(t *testing.T, got *tokenrequest.TokenRequest, err error) {
		t.Helper()
		want := &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType, Scope: "read"}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("ReadArtifact() = (%#v, %v), want (%#v, nil)", got, err, want)
		}
	}
	assertError := func(category error) func(*testing.T, *tokenrequest.TokenRequest, error) {
		return func(t *testing.T, got *tokenrequest.TokenRequest, err error) {
			t.Helper()
			if got != nil || !errors.Is(err, category) {
				t.Fatalf("ReadArtifact() = (%#v, %v), want (nil, %v)", got, err, category)
			}
		}
	}

	tests := []struct {
		name          string
		reader        *tokenrequest.Reader
		carrier       *http.Request
		options       []tokenrequest.ReaderOption
		assert        func(*testing.T, *tokenrequest.TokenRequest, error)
		assertOptions bool
	}{
		{name: "reads request", reader: mustReader(t), carrier: request(), assert: assertRead},
		{name: "configured and per-call runtime options", reader: mustReader(t, tokenrequest.WithReaderRuntimeOptions(decorate("runtime"))), carrier: request(), options: []tokenrequest.ReaderOption{decorate("per-call")}, assert: assertRead, assertOptions: true},
		{name: "nil receiver", carrier: request(), assert: assertError(vapi.ErrMisconfigured)},
		{name: "nil request", reader: mustReader(t), assert: assertError(vapi.ErrMalformed)},
		{name: "nil reader option", reader: mustReader(t), carrier: request(), options: []tokenrequest.ReaderOption{nil}, assert: assertError(vapi.ErrMisconfigured)},
		{name: "nil configured reader option", reader: mustReader(t, tokenrequest.WithReaderRuntimeOptions(nil)), carrier: request(), assert: assertError(vapi.ErrMisconfigured)},
		{name: "reader option returns nil", reader: mustReader(t), carrier: request(), options: []tokenrequest.ReaderOption{func(tokenrequest.ReadFunc) tokenrequest.ReadFunc { return nil }}, assert: assertError(vapi.ErrMisconfigured)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optionOrder = nil
			got, err := tt.reader.ReadArtifact(context.Background(), tt.carrier, tt.options...)
			tt.assert(t, got, err)
			if tt.assertOptions {
				want := []string{"runtime before", "per-call before", "per-call after", "runtime after"}
				if !reflect.DeepEqual(optionOrder, want) {
					t.Errorf("reader option order = %#v, want %#v", optionOrder, want)
				}
			}
		})
	}
}

func TestNewReader(t *testing.T) {
	assertCreated := func(t *testing.T, got *tokenrequest.Reader, err error) {
		t.Helper()
		if err != nil || got == nil {
			t.Fatalf("NewReader() = (%#v, %v), want a reader and nil error", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *tokenrequest.Reader, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewReader() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}

	tests := []struct {
		name    string
		options []tokenrequest.ReaderConfigOption
		assert  func(*testing.T, *tokenrequest.Reader, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "dependency options", options: []tokenrequest.ReaderConfigOption{
			tokenrequest.WithReaderTokenDecoderOptions(),
			tokenrequest.WithReaderAssertionTokenDecoderOptions(),
			tokenrequest.WithReaderClientCredentialsReaderOptions(),
		}, assert: assertCreated},
		{name: "nil config option", options: []tokenrequest.ReaderConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil token decoder", options: []tokenrequest.ReaderConfigOption{tokenrequest.WithReaderTokenDecoder(nil)}, assert: assertMisconfigured},
		{name: "nil assertion token decoder", options: []tokenrequest.ReaderConfigOption{tokenrequest.WithReaderAssertionTokenDecoder(nil)}, assert: assertMisconfigured},
		{name: "nil client credentials reader", options: []tokenrequest.ReaderConfigOption{tokenrequest.WithReaderClientCredentialsReader(nil)}, assert: assertMisconfigured},
		{name: "invalid token decoder options", options: []tokenrequest.ReaderConfigOption{tokenrequest.WithReaderTokenDecoderOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid assertion token decoder options", options: []tokenrequest.ReaderConfigOption{tokenrequest.WithReaderAssertionTokenDecoderOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid client credentials reader options", options: []tokenrequest.ReaderConfigOption{tokenrequest.WithReaderClientCredentialsReaderOptions(nil)}, assert: assertMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenrequest.NewReader(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func mustReader(t *testing.T, options ...tokenrequest.ReaderConfigOption) *tokenrequest.Reader {
	t.Helper()
	reader, err := tokenrequest.NewReader(options...)
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}
	return reader
}
