package token

import (
	"context"
	"fmt"

	"github.com/veles-security/vapi"
)

type EncodeFunc func(context.Context, AnyToken) ([]byte, error)
type EncodeGeneric[T AnyToken, O any] func(ctx context.Context, artifact T, options ...O) ([]byte, error)

type Encoder struct {
	encoders map[string]EncodeFunc
}

type EncoderOption func(*Encoder)

func WithToken[T AnyToken, O any](tokenType string, encode EncodeGeneric[T, O]) EncoderOption {
	return func(encoder *Encoder) {
		encoder.encoders[tokenType] = func(ctx context.Context, token AnyToken) ([]byte, error) {
			artifact, ok := token.(T)
			if !ok {
				return nil, fmt.Errorf("%w: invalid token type %q", vapi.ErrMalformed, tokenType)
			}
			return encode(ctx, artifact)
		}
	}
}

func NewEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{encoders: make(map[string]EncodeFunc, len(options))}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

func (r *Encoder) EncodeToken(
	ctx context.Context,
	token AnyToken,
) ([]byte, error) {
	if token == nil {
		return nil, vapi.ErrMalformed
	}

	encode, ok := r.encoders[token.TokenType()]
	if !ok {
		return nil, fmt.Errorf(
			"%w: unsupported token type %q",
			vapi.ErrMalformed,
			token.TokenType(),
		)
	}

	return encode(ctx, token)
}
