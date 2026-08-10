package jwt

import (
	"context"
	"errors"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
)

func WithStandardClaims() ArtifactAuthenticatorOption {
	numericDate := func(value any) (time.Time, bool) {
		seconds, ok := value.(float64)
		if !ok {
			return time.Time{}, false
		}
		whole := int64(seconds)
		nanos := int64((seconds - float64(whole)) * 1e9)
		return time.Unix(whole, nanos).UTC(), true
	}

	return func(next AuthenticateArtifactFunc) AuthenticateArtifactFunc {

		return func(ctx context.Context, token *Token) (vapi.Principal, error) {
			principal, err := next(ctx, token)
			if err != nil {
				return nil, err
			}
			p, ok := principal.(*sub.Principal)
			if !ok {
				return nil, errors.New("voauth: standard claims mapper requires *sub.Principal")
			}

			p.WithClaims(token.Claims)
			if value, ok := token.Claims["name"].(string); ok {
				p.WithDisplayName(value)
			}
			if value, ok := token.Claims["preferred_username"].(string); ok {
				p.WithUsername(value)
			}
			if value, ok := token.Claims["email"].(string); ok {
				p.WithEmail(value)
			}
			if value, ok := numericDate(token.Claims["iat"]); ok {
				p.WithIssuedAt(value)
			}
			if value, ok := numericDate(token.Claims["auth_time"]); ok {
				p.WithAuthenticatedAt(value)
			}
			p.WithSource("oauth2:jwt")

			return p, nil
		}
	}
}
