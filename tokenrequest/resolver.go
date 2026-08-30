package tokenrequest

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

type Resolver struct {
	clientResolver vapi.Resolver[*clientcredentials.ClientCredentials, clientcredentials.ResolverOption]
	runtimeOptions []ResolverOption
}

type ResolverConfigOption func(*Resolver) error

type ResolveFunc func(ctx context.Context, artifact *TokenRequest, clientPrincipal vapi.Principal) (vapi.Principal, error)

type ResolverOption func(next ResolveFunc) ResolveFunc

func NewResolver(configOptions ...ResolverConfigOption) (*Resolver, error) {
	resolver := &Resolver{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil resolver config option"))
		}
		if err := option(resolver); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if resolver.clientResolver == nil {
		clientResolver, err := clientcredentials.NewResolver()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		resolver.clientResolver = clientResolver
	}
	return resolver, nil
}

// Resolve implements [vapi.Resolver].
func (r *Resolver) Resolve(ctx context.Context, artifact *TokenRequest, options ...ResolverOption) (vapi.Principal, error) {
	if r == nil || r.clientResolver == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot resolve token request with invalid resolver configuration"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot resolve nil token request"))
	}

	allOptions := slices.Concat(r.runtimeOptions, options)

	next := r.resolve
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
	clientPrincipal, err := r.clientResolver.Resolve(ctx, &artifact.ClientCredentials)
	if err != nil {
		return nil, fmt.Errorf("resolve client credentials: %w", err)
	}
	if clientPrincipal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client credentials resolver returned nil principal"))
	}
	return next(ctx, artifact, clientPrincipal)
}

func (r *Resolver) resolve(_ context.Context, _ *TokenRequest, clientPrincipal vapi.Principal) (vapi.Principal, error) {
	return clientPrincipal, nil
}

var _ vapi.Resolver[*TokenRequest, ResolverOption] = &Resolver{}
