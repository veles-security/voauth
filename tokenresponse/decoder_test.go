package tokenresponse

import (
	"context"
	"errors"
	"testing"

	"github.com/veles-security/vapi"
)

func TestNewDecoder(t *testing.T) {
	assertCreated := func(t *testing.T, got *Decoder, err error) {
		t.Helper()
		if err != nil || got == nil {
			t.Fatalf("NewDecoder() = (%#v, %v), want configured decoder", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *Decoder, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewDecoder() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}

	tests := []struct {
		name    string
		options []DecoderConfigOption
		assert  func(*testing.T, *Decoder, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "payload limit", options: []DecoderConfigOption{WithDecoderMaxPayloadBytes(1024)}, assert: assertCreated},
		{name: "invalid payload limit", options: []DecoderConfigOption{WithDecoderMaxPayloadBytes(0)}, assert: assertMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecoder(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func TestDecoder_DecodePayloadLimit(t *testing.T) {
	decoder, err := NewDecoder(WithDecoderMaxPayloadBytes(4))
	if err != nil {
		t.Fatalf("NewDecoder() failed: %v", err)
	}
	artifact, err := decoder.Decode(context.Background(), []byte(`{"access_token":"oversized"}`))
	if artifact != nil || !errors.Is(err, vapi.ErrMalformed) {
		t.Fatalf("Decode() = (%#v, %v), want (nil, %v)", artifact, err, vapi.ErrMalformed)
	}
}
