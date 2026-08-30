package jwt

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
)

type Resolver struct {
	runtimeOptions []ResolverOption
}

type ResolverConfigOption func(*Resolver) error

type ResolveFunc func(ctx context.Context, artifact *Token) (vapi.Principal, error)

type ResolverOption func(next ResolveFunc) ResolveFunc

func NewResolver(configOptions ...ResolverConfigOption) (*Resolver, error) {
	authenticator := &Resolver{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil resolver config option"))
		}
		if err := option(authenticator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return authenticator, nil
}

// Resolve implements [vapi.Resolver].
func (a *Resolver) Resolve(ctx context.Context, artifact *Token, options ...ResolverOption) (vapi.Principal, error) {
	if a == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot resolve JWT with nil resolver"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot resolve nil JWT"))
	}

	allOptions := slices.Concat(a.runtimeOptions, options)

	next := a.resolve
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil resolver option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("resolver option at index %d returned nil ResolveFunc", index))
		}
		next = wrapped
	}

	return next(ctx, artifact)
}

func (a *Resolver) resolve(_ context.Context, artifact *Token) (vapi.Principal, error) {
	issuer, _ := artifact.Claims["iss"].(string)
	subject, _ := artifact.Claims["sub"].(string)
	principal := sub.NewBasePrincipal(issuer, subject, "oauth2:principal")
	return principal, nil
}

var _ vapi.Resolver[*Token, ResolverOption] = &Resolver{}
