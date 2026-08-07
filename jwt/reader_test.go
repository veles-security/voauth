package jwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
)

type readerDecoderStub struct {
	artifact *Token
	err      error
}

func (d *readerDecoderStub) Decode(context.Context, []byte, ...DecoderOption) (*Token, error) {
	return d.artifact, d.err
}

func TestNewReader(t *testing.T) {
	cause := errors.New("config failure")

	assertCreated := func(t *testing.T, got *Reader, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("NewReader() failed: %v", err)
		}
		if got == nil || got.decoder == nil {
			t.Fatalf("NewReader() = %#v, want configured reader", got)
		}
	}
	assertMisconfigured := func(t *testing.T, got *Reader, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewReader() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	assertCause := func(t *testing.T, got *Reader, err error) {
		t.Helper()
		assertMisconfigured(t, got, err)
		if !errors.Is(err, cause) {
			t.Errorf("NewReader() error = %v, want preserved cause %v", err, cause)
		}
	}

	tests := []struct {
		name    string
		options []ReaderConfigOption
		assert  func(*testing.T, *Reader, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "direct dependency", options: []ReaderConfigOption{WithReaderDecoder(&readerDecoderStub{})}, assert: assertCreated},
		{name: "dependency options", options: []ReaderConfigOption{WithReaderDecoderOptions()}, assert: assertCreated},
		{name: "runtime options", options: []ReaderConfigOption{WithReaderRuntimeOptions()}, assert: assertCreated},
		{name: "nil option", options: []ReaderConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil dependency", options: []ReaderConfigOption{WithReaderDecoder(nil)}, assert: assertMisconfigured},
		{name: "invalid dependency options", options: []ReaderConfigOption{WithReaderDecoderOptions(DecoderConfigOption(nil))}, assert: assertMisconfigured},
		{name: "option failure", options: []ReaderConfigOption{func(*Reader) error { return cause }}, assert: assertCause},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewReader(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func TestReader_ReadArtifact(t *testing.T) {
	want := &Token{Header: map[string]string{"typ": "JWT"}, Claims: map[string]any{"sub": "subject"}}
	cause := errors.New("decode failure")
	order := []string{}
	decorate := func(name string) ReaderOption {
		return func(next ReadFunc) ReadFunc {
			return func(ctx context.Context, carrier *http.Request) (*Token, error) {
				order = append(order, name)
				return next(ctx, carrier)
			}
		}
	}

	reader, err := NewReader(
		WithReaderDecoder(&readerDecoderStub{artifact: want}),
		WithReaderRuntimeOptions(decorate("configured")),
	)
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}
	decodeFailure, err := NewReader(WithReaderDecoder(&readerDecoderStub{err: cause}))
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}
	nilArtifact, err := NewReader(WithReaderDecoder(&readerDecoderStub{}))
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}

	bearer := httptest.NewRequest(http.MethodGet, "/", nil)
	bearer.Header.Set("Authorization", "Bearer encoded.jwt.token")
	missing := httptest.NewRequest(http.MethodGet, "/", nil)
	malformed := httptest.NewRequest(http.MethodGet, "/", nil)
	malformed.Header.Set("Authorization", "Bearer")

	assertRead := func(t *testing.T, got *Token, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("ReadArtifact() failed: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ReadArtifact() = %#v, want %#v", got, want)
		}
	}
	assertCategory := func(category error) func(*testing.T, *Token, error) {
		return func(t *testing.T, got *Token, err error) {
			t.Helper()
			if got != nil || !errors.Is(err, category) {
				t.Fatalf("ReadArtifact() = (%#v, %v), want (nil, %v)", got, err, category)
			}
		}
	}
	assertDecodeFailure := func(t *testing.T, got *Token, err error) {
		t.Helper()
		assertCategory(vapi.ErrMalformed)(t, got, err)
		if !errors.Is(err, cause) {
			t.Errorf("ReadArtifact() error = %v, want preserved cause %v", err, cause)
		}
	}

	tests := []struct {
		name      string
		reader    *Reader
		carrier   *http.Request
		options   []ReaderOption
		assert    func(*testing.T, *Token, error)
		wantOrder []string
	}{
		{name: "read", reader: reader, carrier: bearer, options: []ReaderOption{decorate("per-call")}, assert: assertRead, wantOrder: []string{"configured", "per-call"}},
		{name: "nil reader", carrier: bearer, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "invalid reader", reader: &Reader{}, carrier: bearer, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil carrier", reader: reader, assert: assertCategory(vapi.ErrMalformed)},
		{name: "not applicable", reader: reader, carrier: missing, assert: assertCategory(vapi.ErrNotApplicable)},
		{name: "malformed credentials", reader: reader, carrier: malformed, assert: assertCategory(vapi.ErrUnauthenticated)},
		{name: "decode failure", reader: decodeFailure, carrier: bearer, assert: assertDecodeFailure},
		{name: "nil decoded artifact", reader: nilArtifact, carrier: bearer, assert: assertCategory(vapi.ErrMalformed)},
		{name: "nil option", reader: reader, carrier: bearer, options: []ReaderOption{nil}, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil decorator", reader: reader, carrier: bearer, options: []ReaderOption{func(ReadFunc) ReadFunc { return nil }}, assert: assertCategory(vapi.ErrMisconfigured)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = nil
			got, gotErr := tt.reader.ReadArtifact(context.Background(), tt.carrier, tt.options...)
			tt.assert(t, got, gotErr)
			if tt.wantOrder != nil && !reflect.DeepEqual(order, tt.wantOrder) {
				t.Errorf("ReadArtifact() option order = %v, want %v", order, tt.wantOrder)
			}
		})
	}
}

var _ vapi.Decoder[*Token, DecoderOption] = &readerDecoderStub{}
