package jwt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/veles-security/vapi"
)

type JwtDecoder struct{}

type JwtDecoderOption func(*JwtDecoder)

func NewJwtDecoder(options ...JwtDecoderOption) *JwtDecoder {
	decoder := &JwtDecoder{}
	for _, option := range options {
		option(decoder)
	}
	return decoder
}

// Decode implements [vapi.DecodeSchemer].
func (d JwtDecoder) Decode(ctx context.Context, encoded []byte, options ...JwtDecoderOption) (*JwtToken, error) {
	headerEncoded, claimsEncoded, signatureEncoded, err := d.split(encoded)
	if err != nil {
		return &JwtToken{}, err
	}
	header, err := d.decodeHeader(headerEncoded)
	if err != nil {
		return &JwtToken{}, err
	}
	claims, err := d.decodeClaims(claimsEncoded)
	if err != nil {
		return &JwtToken{}, err
	}

	return &JwtToken{
		Header:    header,
		Claims:    claims,
		signature: signatureEncoded,
	}, nil
}

func (d JwtDecoder) decodeClaims(claimsEncoded []byte) (map[string]any, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(claimsEncoded)))
	n, err := base64.RawURLEncoding.Decode(decoded, claimsEncoded)
	if err != nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: err}
	}

	claims := make(map[string]any)
	if err := json.Unmarshal(decoded[:n], &claims); err != nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: err}
	}
	return claims, nil
}

func (d JwtDecoder) decodeHeader(headerEncoded []byte) (map[string]string, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(headerEncoded)))
	n, err := base64.RawURLEncoding.Decode(decoded, headerEncoded)
	if err != nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: err}
	}

	header := make(map[string]string)
	if err := json.Unmarshal(decoded[:n], &header); err != nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: err}
	}
	return header, nil
}

func (d JwtDecoder) split(jwtBytes []byte) (header, payload, signature []byte, err error) {
	firstDot := bytes.IndexByte(jwtBytes, '.')
	if firstDot <= 0 {
		return nil, nil, nil, vapi.ErrMalformed
	}

	remainder := jwtBytes[firstDot+1:]
	secondDot := bytes.IndexByte(remainder, '.')
	if secondDot <= 0 || bytes.IndexByte(remainder[secondDot+1:], '.') >= 0 {
		return nil, nil, nil, vapi.ErrMalformed
	}

	return jwtBytes[:firstDot], remainder[:secondDot], remainder[secondDot+1:], nil
}

var _ vapi.Decoder[*JwtToken, JwtDecoderOption] = &JwtDecoder{}
