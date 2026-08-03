package jwt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/veles-security/vapi"
)

type Decoder struct{}

type DecoderOption func(*Decoder)

func NewJwtDecoder(options ...DecoderOption) *Decoder {
	decoder := &Decoder{}
	for _, option := range options {
		option(decoder)
	}
	return decoder
}

// Decode implements [vapi.DecodeSchemer].
func (d Decoder) Decode(ctx context.Context, encoded []byte, options ...DecoderOption) (*Token, error) {
	headerEncoded, claimsEncoded, signatureEncoded, err := d.split(encoded)
	if err != nil {
		return &Token{}, err
	}
	header, err := d.decodeHeader(headerEncoded)
	if err != nil {
		return &Token{}, err
	}
	claims, err := d.decodeClaims(claimsEncoded)
	if err != nil {
		return &Token{}, err
	}

	return &Token{
		Header:    header,
		Claims:    claims,
		signature: signatureEncoded,
	}, nil
}

func (d Decoder) decodeClaims(claimsEncoded []byte) (map[string]any, error) {
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

func (d Decoder) decodeHeader(headerEncoded []byte) (map[string]string, error) {
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

func (d Decoder) split(jwtBytes []byte) (header, payload, signature []byte, err error) {
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

var _ vapi.Decoder[*Token, DecoderOption] = &Decoder{}
