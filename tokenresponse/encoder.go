package tokenresponse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Encoder struct {
	tokenEncoder token.AnyTokenEncoder
}

type EncoderConfigOption func(*Encoder) error

type EncodeFunc func(ctx context.Context, artifact *TokenResponse, representation *TokenResponseRepresentation) error

type EncoderOption func(next EncodeFunc) EncodeFunc

func NewEncoder(configOptions ...EncoderConfigOption) (*Encoder, error) {
	writer := &Encoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil writer config option"))
		}
		if err := option(writer); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if writer.tokenEncoder == nil {
		tokenEcoder, err := jwt.NewEncoder()
		if err != nil {
			return nil, err
		}
		writer.tokenEncoder = tokenEcoder
	}
	return writer, nil
}

// WriteArtifact implements [vapi.Encoder].
func (e *Encoder) Encode(ctx context.Context, artifact *TokenResponse, options ...EncoderOption) ([]byte, error) {
	if e == nil || e.tokenEncoder == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot encode token response with nil token encoder"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode nil token response"))
	}
	if artifact.AccessToken == nil && artifact.RefreshToken == nil && artifact.IdToken == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode token response without a token"))
	}

	representation := &TokenResponseRepresentation{}
	next := e.encode
	for index := len(options) - 1; index >= 0; index-- {
		if options[index] == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil encoder option at index %d", index))
		}
		next = options[index](next)
		if next == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("encoder option at index %d returned nil EncodeFunc", index))
		}
	}
	if err := next(ctx, artifact, representation); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(representation)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode token response representation: %w", err))
	}
	return payload, nil
}

func (e *Encoder) encode(ctx context.Context, artifact *TokenResponse, representation *TokenResponseRepresentation) error {
	representation.TokenType = artifact.TokenType
	representation.ExpiresIn = int64(artifact.ExpiresIn / time.Second)
	representation.Scope = artifact.Scope
	representation.IssuedTokenType = artifact.IssuedTokenType
	representation.Resources = artifact.Resources

	if artifact.AccessToken != nil {
		accessToken, err := e.tokenEncoder.EncodeAnyToken(ctx, artifact.AccessToken)
		if err != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode access token: %w", err))
		}
		representation.AccessToken = string(accessToken)
	}
	if artifact.RefreshToken != nil {
		refreshToken, encodeErr := e.tokenEncoder.EncodeAnyToken(ctx, artifact.RefreshToken)
		if encodeErr != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode refresh token: %w", encodeErr))
		}
		representation.RefreshToken = string(refreshToken)
	}
	if artifact.IdToken != nil {
		idToken, encodeErr := e.tokenEncoder.EncodeAnyToken(ctx, artifact.IdToken)
		if encodeErr != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode ID token: %w", encodeErr))
		}
		representation.IdToken = string(idToken)
	}
	return nil
}

var _ vapi.Encoder[*TokenResponse, EncoderOption] = &Encoder{}
