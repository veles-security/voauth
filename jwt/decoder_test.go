package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
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
		{name: "limits", options: []DecoderConfigOption{WithDecoderMaxTokenBytes(128), WithDecoderMaxHeaderBytes(32), WithDecoderMaxClaimsBytes(64), WithDecoderMaxSignatureBytes(32)}, assert: assertCreated},
		{name: "invalid token limit", options: []DecoderConfigOption{WithDecoderMaxTokenBytes(0)}, assert: assertMisconfigured},
		{name: "invalid header limit", options: []DecoderConfigOption{WithDecoderMaxHeaderBytes(0)}, assert: assertMisconfigured},
		{name: "invalid claims limit", options: []DecoderConfigOption{WithDecoderMaxClaimsBytes(0)}, assert: assertMisconfigured},
		{name: "invalid signature limit", options: []DecoderConfigOption{WithDecoderMaxSignatureBytes(0)}, assert: assertMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecoder(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func TestDecoder_DecodeLimits(t *testing.T) {
	segment := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(value))
	}
	valid := segment(`{"alg":"none"}`) + "." + segment(`{"sub":"subject"}`) + ".signature"

	tests := []struct {
		name    string
		payload string
		options []DecoderConfigOption
	}{
		{name: "compact token", payload: valid, options: []DecoderConfigOption{WithDecoderMaxTokenBytes(len(valid) - 1)}},
		{name: "header", payload: valid, options: []DecoderConfigOption{WithDecoderMaxHeaderBytes(4)}},
		{name: "claims", payload: valid, options: []DecoderConfigOption{WithDecoderMaxClaimsBytes(4)}},
		{name: "signature", payload: strings.TrimSuffix(valid, "signature") + segment("oversized-signature"), options: []DecoderConfigOption{WithDecoderMaxSignatureBytes(4)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder, err := NewDecoder(tt.options...)
			if err != nil {
				t.Fatalf("NewDecoder() failed: %v", err)
			}
			artifact, err := decoder.Decode(context.Background(), []byte(tt.payload))
			if artifact != nil || !errors.Is(err, vapi.ErrMalformed) {
				t.Fatalf("Decode() = (%#v, %v), want (nil, %v)", artifact, err, vapi.ErrMalformed)
			}
		})
	}
}
