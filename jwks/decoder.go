package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwk"
)

type Decoder struct {
	jwkDecoder vapi.Decoder[*jwk.Jwk, jwk.DecoderOption]
}

type DecoderConfigOption func(*Decoder) error

type DecodeFunc func(ctx context.Context, payload []byte) (*Jwks, error)

type DecoderOption func(next DecodeFunc) DecodeFunc

func NewDecoder(configOptions ...DecoderConfigOption) (*Decoder, error) {
	decoder := &Decoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil decoder config option"))
		}
		if err := option(decoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if decoder.jwkDecoder == nil {
		decoder.jwkDecoder = &jwk.Decoder{}
	}
	return decoder, nil
}

// Decode implements [vapi.Decoder].
func (d *Decoder) Decode(ctx context.Context, payload []byte, options ...DecoderOption) (*Jwks, error) {
	if d == nil || d.jwkDecoder == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot decode JWKS with nil JWK decoder"))
	}
	if payload == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot decode nil JWKS payload"))
	}

	next := d.decode
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil decoder option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("decoder option at index %d returned nil DecodeFunc", index))
		}
		next = wrapped
	}
	return next(ctx, payload)
}

func (d *Decoder) decode(ctx context.Context, payload []byte) (*Jwks, error) {
	var representation JwksRepresentation
	if err := json.Unmarshal(payload, &representation); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWKS representation: %w", err))
	}
	if representation.Keys == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing JWK set keys"))
	}
	if len(representation.Keys) == 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot decode empty JWK set"))
	}

	result := &Jwks{Keys: make([]jwk.Jwk, len(representation.Keys))}
	for i := range representation.Keys {
		encoded, err := json.Marshal(&representation.Keys[i])
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWK representation at index %d: %w", i, err))
		}
		decoded, err := d.jwkDecoder.Decode(ctx, encoded)
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWK at index %d: %w", i, err))
		}
		if decoded == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWK at index %d returned nil artifact", i))
		}
		result.Keys[i] = *decoded
	}
	return result, nil
}

var _ vapi.Decoder[*Jwks, DecoderOption] = &Decoder{}
