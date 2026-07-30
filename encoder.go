package velesoauth

import (
	"context"
	"encoding/base64"
	"encoding/json"

	velesapi "github.com/veles-security/vapi"
)

type JwtEncoder struct {
}

type JwtEncoderOption struct {
}

// Encode implements [vapi.EncodeSchemer].
func (j *JwtEncoder) Encode(ctx context.Context, artifact *JwtToken, options ...JwtEncoderOption) ([]byte, error) {
	header, err := json.Marshal(artifact.header)
	if err != nil {
		return nil, err
	}
	claims, err := json.Marshal(artifact.claims)
	if err != nil {
		return nil, err
	}

	headerLen := base64.RawURLEncoding.EncodedLen(len(header))
	claimsLen := base64.RawURLEncoding.EncodedLen(len(claims))
	encoded := make([]byte, headerLen+claimsLen+len(artifact.signature)+2)
	base64.RawURLEncoding.Encode(encoded[:headerLen], header)
	encoded[headerLen] = '.'
	base64.RawURLEncoding.Encode(encoded[headerLen+1:headerLen+1+claimsLen], claims)
	encoded[headerLen+1+claimsLen] = '.'
	copy(encoded[headerLen+claimsLen+2:], artifact.signature)
	return encoded, nil
}

// ----------------------------------------------------------------------------

type JwtClaimsEncoder struct {
}

type JwtClaimsEncoderOption struct {
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
