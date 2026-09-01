package clientcredentials_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type tokenDecoderStub struct {
	artifact token.AnyToken
	err      error
}

func (d *tokenDecoderStub) DecodeAnyToken(context.Context, []byte) (token.AnyToken, error) {
	return d.artifact, d.err
}

func TestReader_ReadArtifact(t *testing.T) {
	assertRead := func(t *testing.T, got *clientcredentials.ClientCredentials, err error) {
		if err != nil || got == nil {
			t.Fatalf("ReadArtifact() = (%#v, %v), want credentials", got, err)
		}
	}
	assertCategory := func(category error) func(*testing.T, *clientcredentials.ClientCredentials, error) {
		return func(t *testing.T, got *clientcredentials.ClientCredentials, err error) {
			if got != nil || !errors.Is(err, category) {
				t.Fatalf("ReadArtifact() = (%#v, %v), want (nil, %v)", got, err, category)
			}
		}
	}

	order := []string{}
	decorate := func(name string) clientcredentials.ReaderOption {
		return func(next clientcredentials.ReadFunc) clientcredentials.ReadFunc {
			return func(ctx context.Context, carrier *http.Request) (*clientcredentials.ClientCredentials, error) {
				order = append(order, name+"-before")
				artifact, err := next(ctx, carrier)
				order = append(order, name+"-after")
				return artifact, err
			}
		}
	}
	reader, err := clientcredentials.NewReader(clientcredentials.WithReaderRuntimeOptions(decorate("runtime")))
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}
	basic := httptest.NewRequest("POST", "/token", nil)
	basic.SetBasicAuth(url.QueryEscape("client id"), url.QueryEscape("secret value"))
	post := httptest.NewRequest("POST", "/token", strings.NewReader("client_id=id&client_secret=secret"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	none := httptest.NewRequest("POST", "/token", nil)
	multiple := httptest.NewRequest("POST", "/token", strings.NewReader("client_secret=secret"))
	multiple.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	multiple.SetBasicAuth("id", "secret")
	oversized := httptest.NewRequest("POST", "/token", strings.NewReader("client_id=id&client_secret=secret"))
	oversized.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tests := []struct {
		name    string
		reader  *clientcredentials.Reader
		request *http.Request
		options []clientcredentials.ReaderOption
		assert  func(*testing.T, *clientcredentials.ClientCredentials, error)
	}{
		{name: "basic", reader: reader, request: basic, assert: assertRead},
		{name: "post", reader: reader, request: post, options: []clientcredentials.ReaderOption{decorate("call")}, assert: assertRead},
		{name: "not applicable", reader: reader, request: none, assert: assertCategory(vapi.ErrNotApplicable)},
		{name: "multiple methods", reader: reader, request: multiple, assert: assertCategory(vapi.ErrUnauthenticated)},
		{name: "oversized body", reader: mustLimitedReader(t, 4), request: oversized, assert: assertCategory(vapi.ErrMalformed)},
		{name: "nil receiver", request: basic, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil request", reader: reader, assert: assertCategory(vapi.ErrMalformed)},
		{name: "nil option", reader: reader, request: basic, options: []clientcredentials.ReaderOption{nil}, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil decorator", reader: reader, request: basic, options: []clientcredentials.ReaderOption{func(clientcredentials.ReadFunc) clientcredentials.ReadFunc { return nil }}, assert: assertCategory(vapi.ErrMisconfigured)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = order[:0]
			got, gotErr := tt.reader.ReadArtifact(context.Background(), tt.request, tt.options...)
			tt.assert(t, got, gotErr)
			if tt.name == "post" {
				want := []string{"runtime-before", "call-before", "call-after", "runtime-after"}
				if !reflect.DeepEqual(order, want) {
					t.Errorf("decorator order = %#v, want %#v", order, want)
				}
			}
		})
	}
}

func TestNewReader(t *testing.T) {
	assertCreated := func(t *testing.T, got *clientcredentials.Reader, err error) {
		if err != nil || got == nil {
			t.Fatalf("NewReader() = (%#v, %v), want reader", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *clientcredentials.Reader, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewReader() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []clientcredentials.ReaderConfigOption
		assert  func(*testing.T, *clientcredentials.Reader, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "direct dependency", options: []clientcredentials.ReaderConfigOption{clientcredentials.WithReaderTokenDecoder(&tokenDecoderStub{})}, assert: assertCreated},
		{name: "dependency options", options: []clientcredentials.ReaderConfigOption{clientcredentials.WithReaderTokenDecoderOptions()}, assert: assertCreated},
		{name: "body limit", options: []clientcredentials.ReaderConfigOption{clientcredentials.WithReaderMaxBodyBytes(1024)}, assert: assertCreated},
		{name: "invalid body limit", options: []clientcredentials.ReaderConfigOption{clientcredentials.WithReaderMaxBodyBytes(0)}, assert: assertMisconfigured},
		{name: "nil config option", options: []clientcredentials.ReaderConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil dependency", options: []clientcredentials.ReaderConfigOption{clientcredentials.WithReaderTokenDecoder(nil)}, assert: assertMisconfigured},
		{name: "invalid dependency options", options: []clientcredentials.ReaderConfigOption{clientcredentials.WithReaderTokenDecoderOptions(jwt.DecoderConfigOption(nil))}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := clientcredentials.NewReader(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}

func mustLimitedReader(t *testing.T, maxBytes int64) *clientcredentials.Reader {
	t.Helper()
	reader, err := clientcredentials.NewReader(clientcredentials.WithReaderMaxBodyBytes(maxBytes))
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}
	return reader
}
