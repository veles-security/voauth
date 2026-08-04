package token

import (
	"context"
)

type AnyTokenEncoder interface {
	EncodeAnyToken(ctx context.Context, artifact AnyToken) ([]byte, error)
}
