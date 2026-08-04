package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

type Encoder struct{}

type EncoderOption func(*Encoder)

func NewJwtEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

// Encode implements [vapi.Encoder].
func (j *Encoder) Encode(ctx context.Context, artifact *Token, options ...EncoderOption) ([]byte, error) {
	header, err := json.Marshal(artifact.Header)
	if err != nil {
		return nil, err
	}
	claims, err := json.Marshal(artifact.Claims)
	if err != nil {
		return nil, err
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
func (j *Encoder) EncodeAnyToken(ctx context.Context, artifact token.AnyToken) ([]byte, error) {
	jwtArtifact, ok := artifact.(*Token)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrNotApplicable, errors.New("not a JWT token"))
	}
	return j.Encode(ctx, jwtArtifact)
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
