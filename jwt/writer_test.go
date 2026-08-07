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

type writerEncoderStub struct {
	payload []byte
	err     error
}

func (e *writerEncoderStub) Encode(context.Context, *Token, ...EncoderOption) ([]byte, error) {
	return e.payload, e.err
}

func TestNewWriter(t *testing.T) {
	cause := errors.New("config failure")

	assertCreated := func(t *testing.T, got *Writer, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("NewWriter() failed: %v", err)
		}
		if got == nil || got.encoder == nil {
			t.Fatalf("NewWriter() = %#v, want configured writer", got)
		}
	}
	assertMisconfigured := func(t *testing.T, got *Writer, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewWriter() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	assertCause := func(t *testing.T, got *Writer, err error) {
		t.Helper()
		assertMisconfigured(t, got, err)
		if !errors.Is(err, cause) {
			t.Errorf("NewWriter() error = %v, want preserved cause %v", err, cause)
		}
	}

	tests := []struct {
		name    string
		options []WriterConfigOption
		assert  func(*testing.T, *Writer, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "direct dependency", options: []WriterConfigOption{WithWriterEncoder(&writerEncoderStub{})}, assert: assertCreated},
		{name: "dependency options", options: []WriterConfigOption{WithWriterEncoderOptions()}, assert: assertCreated},
		{name: "runtime options", options: []WriterConfigOption{WithWriterRuntimeOptions()}, assert: assertCreated},
		{name: "nil option", options: []WriterConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil dependency", options: []WriterConfigOption{WithWriterEncoder(nil)}, assert: assertMisconfigured},
		{name: "invalid dependency options", options: []WriterConfigOption{WithWriterEncoderOptions(EncoderConfigOption(nil))}, assert: assertMisconfigured},
		{name: "option failure", options: []WriterConfigOption{func(*Writer) error { return cause }}, assert: assertCause},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewWriter(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func TestWriter_WriteArtifact(t *testing.T) {
	artifact := &Token{Header: map[string]string{"typ": "JWT"}, Claims: map[string]any{"sub": "subject"}}
	cause := errors.New("encode failure")
	order := []string{}
	decorate := func(name string) WriterOption {
		return func(next WriteFunc) WriteFunc {
			return func(ctx context.Context, carrier *http.Request, artifact *Token) error {
				order = append(order, name)
				return next(ctx, carrier, artifact)
			}
		}
	}

	writer, err := NewWriter(
		WithWriterEncoder(&writerEncoderStub{payload: []byte("encoded.jwt.token")}),
		WithWriterRuntimeOptions(decorate("configured")),
	)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	encodeFailure, err := NewWriter(WithWriterEncoder(&writerEncoderStub{err: cause}))
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}

	assertWritten := func(t *testing.T, request *http.Request, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("WriteArtifact() failed: %v", err)
		}
		if got, want := request.Header.Get("Authorization"), "Bearer encoded.jwt.token"; got != want {
			t.Errorf("WriteArtifact() Authorization = %q, want %q", got, want)
		}
	}
	assertCategory := func(category error) func(*testing.T, *http.Request, error) {
		return func(t *testing.T, _ *http.Request, err error) {
			t.Helper()
			if !errors.Is(err, category) {
				t.Fatalf("WriteArtifact() error = %v, want %v", err, category)
			}
		}
	}
	assertEncodeFailure := func(t *testing.T, request *http.Request, err error) {
		t.Helper()
		assertCategory(vapi.ErrMalformed)(t, request, err)
		if !errors.Is(err, cause) {
			t.Errorf("WriteArtifact() error = %v, want preserved cause %v", err, cause)
		}
	}

	tests := []struct {
		name      string
		writer    *Writer
		carrier   *http.Request
		artifact  *Token
		options   []WriterOption
		assert    func(*testing.T, *http.Request, error)
		wantOrder []string
	}{
		{name: "write", writer: writer, carrier: httptest.NewRequest(http.MethodGet, "/", nil), artifact: artifact, options: []WriterOption{decorate("per-call")}, assert: assertWritten, wantOrder: []string{"configured", "per-call"}},
		{name: "nil writer", carrier: httptest.NewRequest(http.MethodGet, "/", nil), artifact: artifact, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "invalid writer", writer: &Writer{}, carrier: httptest.NewRequest(http.MethodGet, "/", nil), artifact: artifact, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil carrier", writer: writer, artifact: artifact, assert: assertCategory(vapi.ErrMalformed)},
		{name: "nil artifact", writer: writer, carrier: httptest.NewRequest(http.MethodGet, "/", nil), assert: assertCategory(vapi.ErrMalformed)},
		{name: "encode failure", writer: encodeFailure, carrier: httptest.NewRequest(http.MethodGet, "/", nil), artifact: artifact, assert: assertEncodeFailure},
		{name: "nil option", writer: writer, carrier: httptest.NewRequest(http.MethodGet, "/", nil), artifact: artifact, options: []WriterOption{nil}, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil decorator", writer: writer, carrier: httptest.NewRequest(http.MethodGet, "/", nil), artifact: artifact, options: []WriterOption{func(WriteFunc) WriteFunc { return nil }}, assert: assertCategory(vapi.ErrMisconfigured)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = nil
			gotErr := tt.writer.WriteArtifact(context.Background(), tt.carrier, tt.artifact, tt.options...)
			tt.assert(t, tt.carrier, gotErr)
			if tt.wantOrder != nil && !reflect.DeepEqual(order, tt.wantOrder) {
				t.Errorf("WriteArtifact() option order = %v, want %v", order, tt.wantOrder)
			}
		})
	}
}

var _ vapi.Encoder[*Token, EncoderOption] = &writerEncoderStub{}
