package velesoauth

import (
	"context"
	"errors"

	velesapi "github.com/veles-security/vapi"
)

type JwtIssuer struct {
	options []JwtIssuerOption
}

func NewJwtIssuer(options ...JwtIssuerOption) *JwtIssuer {
	issuer := &JwtIssuer{}
	issuer.options = options
	return issuer
}

// Issue implements [velesapi.IssueSchemer].
func (j *JwtIssuer) Issue(ctx context.Context, options ...JwtIssuerOption) (*JwtToken, error) {
	token := &JwtToken{
		Header: map[string]string{},
		Claims: make(Cliams),
	}

	applyOptions := func(ps []JwtIssuerOption) error {
		for _, p := range ps {
			err := p.ApplyIssuerOption(ctx, token)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := applyOptions(j.options); err != nil {
		return nil, err
	}
	if err := applyOptions(options); err != nil {
		return nil, err
	}

	return token, nil
}

type JwtIssuerOption interface {
	ApplyIssuerOption(ctx context.Context, token *JwtToken) error
}

type JwtIssuerOptionFunc func(ctx context.Context, token *JwtToken) error

func (f JwtIssuerOptionFunc) ApplyIssuerOption(ctx context.Context, token *JwtToken) error {
	return f(ctx, token)
}

func WithJwtIssuer(issuer string) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["iss"] = issuer
		return nil
	})
}

func WithJwtPrincipal(principal velesapi.Principaler) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if principal == nil {
			return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, errors.New("nil principal"))
		}
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		for name, value := range principal.Claims() {
			token.Claims[name] = value
		}
		token.Claims["sub"] = principal.Subject()
		return nil
	})
}

var _ velesapi.IssueSchemer[JwtIssuerOption, *JwtToken] = &JwtIssuer{}
var _ JwtIssuerOption = JwtIssuerOptionFunc(nil)
