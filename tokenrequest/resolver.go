package tokenrequest

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

type Resolver struct {
	authCallbacks  map[string]AuthCallback
	clientResolver vapi.Resolver[*clientcredentials.ClientCredentials, clientcredentials.ResolverOption]
	runtimeOptions []ResolverOption
}

type ResolverConfigOption func(*Resolver) error

type ResolveFunc func(ctx context.Context, artifact *TokenRequest) (vapi.Principal, error)

type ResolverOption func(next ResolveFunc) ResolveFunc

// AuthCallback resolves the principal for a grant type after the client has
// been resolved.
type AuthCallback func(ctx context.Context, request *TokenRequest, clientPrincipal vapi.Principal) (vapi.Principal, error)

func NewResolver(configOptions ...ResolverConfigOption) (*Resolver, error) {
	resolver := &Resolver{authCallbacks: make(map[string]AuthCallback)}
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
	if r == nil || r.authCallbacks == nil || r.clientResolver == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot resolve token request with invalid resolver configuration"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot resolve nil token request"))
	}

	allOptions := make([]ResolverOption, 0, len(r.runtimeOptions)+len(options))
	allOptions = append(allOptions, r.runtimeOptions...)
	allOptions = append(allOptions, options...)

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
	return next(ctx, artifact)
}

func (r *Resolver) resolve(ctx context.Context, artifact *TokenRequest) (vapi.Principal, error) {
	clientPrincipal, err := r.clientResolver.Resolve(ctx, &artifact.ClientCredentials)
	if err != nil {
		return nil, fmt.Errorf("resolve client credentials: %w", err)
	}
	if clientPrincipal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client credentials resolver returned nil principal"))
	}

	callback, ok := r.authCallbacks[artifact.GrantType]
	if !ok {
		if artifact.GrantType == ClientCredentialsGrantType {
			return clientPrincipal, nil
		}
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("no resolver callback for grant type %q", artifact.GrantType))
	}
	principal, err := callback(ctx, artifact, clientPrincipal)
	if err != nil {
		return nil, fmt.Errorf("resolve token request for grant type %q: %w", artifact.GrantType, err)
	}
	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("resolver callback for grant type %q returned nil principal", artifact.GrantType))
	}
	return principal, nil
}

var _ vapi.Resolver[*TokenRequest, ResolverOption] = &Resolver{}
