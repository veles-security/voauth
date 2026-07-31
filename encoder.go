package voauth

import (
	"context"
	"encoding/base64"
	"encoding/json"

	velesapi "github.com/veles-security/vapi"
)

type JwtEncoder struct{}

type JwtEncoderOption func(*JwtEncoder)

func NewJwtEncoder(options ...JwtEncoderOption) *JwtEncoder {
	encoder := &JwtEncoder{}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

// Encode implements [vapi.EncodeSchemer].
func (j *JwtEncoder) Encode(ctx context.Context, artifact *JwtToken, options ...JwtEncoderOption) ([]byte, error) {
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

// Encode implements [vapi.EncodeSchemer].
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

var _ velesapi.EncodeSchemer[*JwtToken, JwtEncoderOption] = &JwtEncoder{}
var _ velesapi.EncodeSchemer[*Cliams, JwtClaimsEncoderOption] = &JwtClaimsEncoder{}
