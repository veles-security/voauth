package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

type Encoder struct{}

type EncoderConfigOption func(*Encoder) error

type EncodeFunc func(ctx context.Context, artifact *Token) ([]byte, error)

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
	return encoder, nil
}

// Encode implements [vapi.Encoder].
func (e *Encoder) Encode(ctx context.Context, artifact *Token, options ...EncoderOption) ([]byte, error) {
	if e == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot encode JWT with nil encoder"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode nil JWT"))
	}

	next := e.encode
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
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

func (e *Encoder) encode(_ context.Context, artifact *Token) ([]byte, error) {
	header, err := json.Marshal(artifact.Header)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWT header: %w", err))
	}
	claims, err := json.Marshal(artifact.Claims)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWT claims: %w", err))
	}

	headerLen := base64.RawURLEncoding.EncodedLen(len(header))
	headerEncoded := make([]byte, headerLen)
	base64.RawURLEncoding.Encode(headerEncoded, header)

	claimsLen := base64.RawURLEncoding.EncodedLen(len(claims))
	claimsEncoded := make([]byte, claimsLen)
	base64.RawURLEncoding.Encode(claimsEncoded, claims)

	signatureLen := base64.RawURLEncoding.EncodedLen(len(artifact.signature))
	signatureEncoded := make([]byte, signatureLen)
	base64.RawURLEncoding.Encode(signatureEncoded, artifact.signature)

	encoded := make([]byte, headerLen+claimsLen+signatureLen+2)
	offset := copy(encoded, headerEncoded)
	encoded[offset] = '.'
	offset++
	offset += copy(encoded[offset:], claimsEncoded)
	encoded[offset] = '.'
	copy(encoded[offset+1:], signatureEncoded)

	return encoded, nil
}

// implements [token.AnyTokenEncoder].
func (e *Encoder) EncodeAnyToken(ctx context.Context, artifact token.AnyToken) ([]byte, error) {
	jwtArtifact, ok := artifact.(*Token)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrNotApplicable, errors.New("not a JWT token"))
	}
	return e.Encode(ctx, jwtArtifact)
}

// ----------------------------------------------------------------------------

type JwtClaimsEncoder struct{}

type JwtClaimsEncoderOption func(*JwtClaimsEncoder)

func NewJwtClaimsEncoder(options ...JwtClaimsEncoderOption) *JwtClaimsEncoder {
	encoder := &JwtClaimsEncoder{}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

// Encode implements [vapi.Encoder].
func (j *JwtClaimsEncoder) Encode(ctx context.Context, claims *Cliams, options ...JwtClaimsEncoderOption) ([]byte, error) {
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	claimsLen := base64.RawURLEncoding.EncodedLen(len(claimsJson))
	encoded := make([]byte, claimsLen)
	base64.RawURLEncoding.Encode(encoded, claimsJson)
	return encoded, nil
}

var _ vapi.Encoder[*Token, EncoderOption] = &Encoder{}
var _ vapi.Encoder[*Cliams, JwtClaimsEncoderOption] = &JwtClaimsEncoder{}
var _ token.AnyTokenEncoder = &Encoder{}
