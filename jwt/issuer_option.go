package jwt

import (
	"context"
	"errors"
	"maps"
	"time"

	"github.com/veles-security/vapi"
)

func WithSubject(subject string) IssuerOption {
	return func(next IssueFunc) IssueFunc {
		return func(ctx context.Context, token *Token) error {
			token.Claims["sub"] = subject
			return next(ctx, token)
		}
	}
}

func WithIssuer(issuer string) IssuerOption {
	return func(next IssueFunc) IssueFunc {
		return func(ctx context.Context, token *Token) error {
			token.Claims["iss"] = issuer
			return next(ctx, token)
		}
	}
}

func WithExp(exp time.Duration) IssuerOption {
	return func(next IssueFunc) IssueFunc {
		return func(ctx context.Context, token *Token) error {
			token.Claims["exp"] = token.iat.Add(exp).Unix()
			return next(ctx, token)
		}
	}
}

func WithClaims(claims Cliams) IssuerOption {
	return func(next IssueFunc) IssueFunc {
		return func(ctx context.Context, token *Token) error {
			maps.Copy(token.Claims, claims)
			return next(ctx, token)
		}
	}
}

func WithPrincipal(principal vapi.Principal) IssuerOption {
	return func(next IssueFunc) IssueFunc {
		return func(ctx context.Context, token *Token) error {
			if principal == nil {
				return vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("nil principal"))
			}
			maps.Copy(token.Claims, principal.Claims())
			token.Claims["sub"] = principal.Subject()
			return next(ctx, token)
		}
	}
}
