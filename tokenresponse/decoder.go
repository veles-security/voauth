package tokenresponse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Decoder struct {
	tokenDecoder    token.AnyTokenDecoder
	maxPayloadBytes int
	runtimeOptions  []DecoderOption
}

const defaultMaxPayloadBytes = 1024 * 1024

type DecoderConfigOption func(*Decoder) error

type DecodeFunc func(ctx context.Context, payload []byte) (*TokenResponse, error)

type DecoderOption func(next DecodeFunc) DecodeFunc

func NewDecoder(configOptions ...DecoderConfigOption) (*Decoder, error) {
	decoder := &Decoder{maxPayloadBytes: defaultMaxPayloadBytes}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil decoder config option"))
		}
		if err := option(decoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if decoder.tokenDecoder == nil {
		tokenDecoder, err := jwt.NewDecoder()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create default token decoder: %w", err))
		}
		decoder.tokenDecoder = tokenDecoder
	}
	return decoder, nil
}

// Decode implements [vapi.Decoder].
func (d *Decoder) Decode(ctx context.Context, payload []byte, options ...DecoderOption) (*TokenResponse, error) {
	if d == nil || d.tokenDecoder == nil || d.maxPayloadBytes <= 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot decode token response with nil token decoder"))
	}
	if payload == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot decode nil token response payload"))
	}
	if len(payload) > d.maxPayloadBytes {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("token response payload exceeds maximum size of %d bytes", d.maxPayloadBytes))
	}

	allOptions := slices.Concat(d.runtimeOptions, options)

	next := d.decode
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
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

func (d *Decoder) decode(ctx context.Context, payload []byte) (*TokenResponse, error) {
	var representation TokenResponseRepresentation
	if err := json.Unmarshal(payload, &representation); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode token response representation: %w", err))
	}

	result := &TokenResponse{
		TokenType:       representation.TokenType,
		ExpiresIn:       time.Duration(representation.ExpiresIn) * time.Second,
		Scope:           representation.Scope,
		IssuedTokenType: representation.IssuedTokenType,
		Resources:       representation.Resources,
	}

	if representation.AccessToken != "" {
		accessToken, err := d.tokenDecoder.DecodeAnyToken(ctx, []byte(representation.AccessToken))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode access token: %w", err))
		}
		if accessToken == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode access token returned nil artifact"))
		}
		result.AccessToken = accessToken
	}
	if representation.RefreshToken != "" {
		refreshToken, err := d.tokenDecoder.DecodeAnyToken(ctx, []byte(representation.RefreshToken))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode refresh token: %w", err))
		}
		if refreshToken == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode refresh token returned nil artifact"))
		}
		result.RefreshToken = refreshToken
	}
	if representation.IdToken != "" {
		idToken, err := d.tokenDecoder.DecodeAnyToken(ctx, []byte(representation.IdToken))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode id token: %w", err))
		}
		if idToken == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode id token returned nil artifact"))
		}
		result.IdToken = idToken
	}

	if result.AccessToken == nil && result.RefreshToken == nil && result.IdToken == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("no tokens"))
	}

	return result, nil
}

var _ vapi.Decoder[*TokenResponse, DecoderOption] = &Decoder{}
