package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwk"
)

type Encoder struct {
	jwkEncoder     vapi.Encoder[*jwk.Jwk, jwk.EncoderOption]
	runtimeOptions []EncoderOption
}

type EncoderConfigOption func(*Encoder) error

type EncodeFunc func(ctx context.Context, artifact *Jwks) ([]byte, error)

type EncoderOption func(next EncodeFunc) EncodeFunc

func NewEncoder(configOptions ...EncoderConfigOption) (*Encoder, error) {
	encoder := &Encoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil encoder config option"))
		}
		if err := option(encoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if encoder.jwkEncoder == nil {
		encoder.jwkEncoder = &jwk.Encoder{}
	}
	return encoder, nil
}

// Encode implements [vapi.Encoder].
func (e *Encoder) Encode(ctx context.Context, artifact *Jwks, options ...EncoderOption) ([]byte, error) {
	if e == nil || e.jwkEncoder == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot encode JWKS with nil JWK encoder"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode nil JWKS"))
	}
	if artifact.Keys == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode JWKS with nil Keys"))
	}
	if len(artifact.Keys) == 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode empty JWK set"))
	}

	allOptions := make([]EncoderOption, 0, len(e.runtimeOptions)+len(options))
	allOptions = append(allOptions, e.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := e.encode
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil encoder option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("encoder option at index %d returned nil EncodeFunc", index))
		}
		next = wrapped
	}
	return next(ctx, artifact)
}

func (e *Encoder) encode(ctx context.Context, artifact *Jwks) ([]byte, error) {
	representation := JwksRepresentation{Keys: make([]jwk.JwkRepresentation, len(artifact.Keys))}
	for i := range artifact.Keys {
		encoded, err := e.jwkEncoder.Encode(ctx, &artifact.Keys[i])
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWK at index %d: %w", i, err))
		}
		if encoded == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWK at index %d returned nil payload", i))
		}
		if err := json.Unmarshal(encoded, &representation.Keys[i]); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWK representation at index %d: %w", i, err))
		}
	}
	payload, err := json.Marshal(representation)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWKS representation: %w", err))
	}
	return payload, nil
}

var _ vapi.Encoder[*Jwks, EncoderOption] = &Encoder{}
