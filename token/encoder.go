package token

import (
	"context"
)

type AnyTokenEncoder interface {
	EncodeAnyToken(ctx context.Context, artifact AnyToken) ([]byte, error)
}

type AnyTokenDecoder interface {
	DecodeAnyToken(ctx context.Context, payload []byte) (AnyToken, error)
}
