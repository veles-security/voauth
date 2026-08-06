package clientcredentials_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type tokenEncoderStub struct{ payload []byte }

func (e *tokenEncoderStub) EncodeAnyToken(context.Context, token.AnyToken) ([]byte, error) {
	return e.payload, nil
}

func TestWriter_WriteArtifact(t *testing.T) {
	assertWritten := func(t *testing.T, err error) {
		if err != nil {
			t.Fatalf("WriteArtifact() failed: %v", err)
		}
	}
	assertCategory := func(category error) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			if !errors.Is(err, category) {
				t.Fatalf("WriteArtifact() error = %v, want %v", err, category)
			}
		}
	}
	order := []string{}
	decorate := func(name string) clientcredentials.WriterOption {
		return func(next clientcredentials.WriteFunc) clientcredentials.WriteFunc {
			return func(ctx context.Context, carrier *http.Request, artifact *clientcredentials.ClientCredentials) error {
				order = append(order, name+"-before")
				err := next(ctx, carrier, artifact)
				order = append(order, name+"-after")
				return err
			}
		}
	}
	writer, err := clientcredentials.NewWriter(clientcredentials.WithWriterRuntimeOptions(decorate("runtime")))
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	credentials := &clientcredentials.ClientCredentials{ClientId: "id", ClientSecret: "secret"}
	tests := []struct {
		name     string
		writer   *clientcredentials.Writer
		request  *http.Request
		artifact *clientcredentials.ClientCredentials
		options  []clientcredentials.WriterOption
		assert   func(*testing.T, error)
	}{
		{name: "client secret", writer: writer, request: httptest.NewRequest("POST", "/token", nil), artifact: credentials, options: []clientcredentials.WriterOption{decorate("call")}, assert: assertWritten},
		{name: "nil receiver", request: httptest.NewRequest("POST", "/token", nil), artifact: credentials, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil request", writer: writer, artifact: credentials, assert: assertCategory(vapi.ErrMalformed)},
		{name: "nil artifact", writer: writer, request: httptest.NewRequest("POST", "/token", nil), assert: assertCategory(vapi.ErrMalformed)},
		{name: "nil option", writer: writer, request: httptest.NewRequest("POST", "/token", nil), artifact: credentials, options: []clientcredentials.WriterOption{nil}, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil decorator", writer: writer, request: httptest.NewRequest("POST", "/token", nil), artifact: credentials, options: []clientcredentials.WriterOption{func(clientcredentials.WriteFunc) clientcredentials.WriteFunc { return nil }}, assert: assertCategory(vapi.ErrMisconfigured)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = order[:0]
			tt.assert(t, tt.writer.WriteArtifact(context.Background(), tt.request, tt.artifact, tt.options...))
			if tt.name == "client secret" {
				want := []string{"runtime-before", "call-before", "call-after", "runtime-after"}
				if !reflect.DeepEqual(order, want) {
					t.Errorf("decorator order = %#v, want %#v", order, want)
				}
			}
		})
	}
}

func TestNewWriter(t *testing.T) {
	assertCreated := func(t *testing.T, got *clientcredentials.Writer, err error) {
		if err != nil || got == nil {
			t.Fatalf("NewWriter() = (%#v, %v), want writer", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *clientcredentials.Writer, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewWriter() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []clientcredentials.WriterConfigOption
		assert  func(*testing.T, *clientcredentials.Writer, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "direct dependency", options: []clientcredentials.WriterConfigOption{clientcredentials.WithWriterTokenEncoder(&tokenEncoderStub{payload: []byte("token")})}, assert: assertCreated},
		{name: "dependency options", options: []clientcredentials.WriterConfigOption{clientcredentials.WithWriterTokenEncoderOptions()}, assert: assertCreated},
		{name: "nil config option", options: []clientcredentials.WriterConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil dependency", options: []clientcredentials.WriterConfigOption{clientcredentials.WithWriterTokenEncoder(nil)}, assert: assertMisconfigured},
		{name: "invalid dependency options", options: []clientcredentials.WriterConfigOption{clientcredentials.WithWriterTokenEncoderOptions(jwt.EncoderConfigOption(nil))}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := clientcredentials.NewWriter(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}
