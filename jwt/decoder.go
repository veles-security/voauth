package jwt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

type Decoder struct{}

type DecoderConfigOption func(*Decoder) error

type DecodeFunc func(ctx context.Context, payload []byte) (*Token, error)

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
	return decoder, nil
}

// Decode implements [vapi.Decoder].
func (d *Decoder) Decode(ctx context.Context, payload []byte, options ...DecoderOption) (*Token, error) {
	if d == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot decode JWT with nil decoder"))
	}
	if payload == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot decode nil JWT payload"))
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

func (d *Decoder) decode(_ context.Context, encoded []byte) (*Token, error) {
	headerEncoded, claimsEncoded, signatureEncoded, err := d.split(encoded)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("split JWT: %w", err))
	}
	header, err := d.decodeHeader(headerEncoded)
	if err != nil {
		return nil, err
	}
	claims, err := d.decodeClaims(claimsEncoded)
	if err != nil {
		return nil, err
	}

	return &Token{
		Header:    header,
		Claims:    claims,
		signature: signatureEncoded,
	}, nil
}

func (d *Decoder) decodeClaims(claimsEncoded []byte) (map[string]any, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(claimsEncoded)))
	n, err := base64.RawURLEncoding.Decode(decoded, claimsEncoded)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWT claims: %w", err))
	}

	claims := make(map[string]any)
	if err := json.Unmarshal(decoded[:n], &claims); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWT claims JSON: %w", err))
	}
	return claims, nil
}

func (d *Decoder) decodeHeader(headerEncoded []byte) (map[string]string, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(headerEncoded)))
	n, err := base64.RawURLEncoding.Decode(decoded, headerEncoded)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWT header: %w", err))
	}

	header := make(map[string]string)
	if err := json.Unmarshal(decoded[:n], &header); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWT header JSON: %w", err))
	}
	return header, nil
}

func (d *Decoder) split(jwtBytes []byte) (header, payload, signature []byte, err error) {
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
