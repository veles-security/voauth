package clientcredentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

type Resolver struct{ runtimeOptions []ResolverOption }
type ResolverConfigOption func(*Resolver) error
type ResolveFunc func(context.Context, *ClientCredentials) (vapi.Principal, error)
type ResolverOption func(ResolveFunc) ResolveFunc

func NewResolver(options ...ResolverConfigOption) (*Resolver, error) {
	a := &Resolver{}
	for _, option := range options {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil resolver config option"))
		}
		if err := option(a); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return a, nil
}

func (a *Resolver) Resolve(ctx context.Context, artifact *ClientCredentials, options ...ResolverOption) (vapi.Principal, error) {
	if a == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot resolve client credentials with nil resolver"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot resolve nil client credentials"))
	}
	all := append(append(make([]ResolverOption, 0, len(a.runtimeOptions)+len(options)), a.runtimeOptions...), options...)
	next := a.resolve
	for index := len(all) - 1; index >= 0; index-- {
		if all[index] == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil resolver option at index %d", index))
		}
		wrapped := all[index](next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("resolver option at index %d returned nil ResolveFunc", index))
		}
		next = wrapped
	}
	return next(ctx, artifact)
}

func (*Resolver) resolve(_ context.Context, artifact *ClientCredentials) (vapi.Principal, error) {
	return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("no resolver option for client authentication method %q", artifact.AuthMethod))
}

var _ vapi.Resolver[*ClientCredentials, ResolverOption] = &Resolver{}
