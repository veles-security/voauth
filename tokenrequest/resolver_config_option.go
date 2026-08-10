package tokenrequest

import (
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

func WithResolverRuntimeOptions(options ...ResolverOption) ResolverConfigOption {
	return func(resolver *Resolver) error {
		resolver.runtimeOptions = append([]ResolverOption(nil), options...)
		return nil
	}
}

func WithResolverAuthCallback(grantType string, callback AuthCallback) ResolverConfigOption {
	return func(resolver *Resolver) error {
		if grantType == "" {
			return errors.New("empty grant type")
		}
		if callback == nil {
			return fmt.Errorf("nil resolver callback for grant type %q", grantType)
		}
		resolver.authCallbacks[grantType] = callback
		return nil
	}
}

func WithResolverClientResolver(resolver vapi.Resolver[*clientcredentials.ClientCredentials, clientcredentials.ResolverOption]) ResolverConfigOption {
	return func(tokenRequestResolver *Resolver) error {
		if resolver == nil {
			return errors.New("nil client credentials resolver")
		}
		tokenRequestResolver.clientResolver = resolver
		return nil
	}
}

func WithResolverClientResolverOptions(options ...clientcredentials.ResolverConfigOption) ResolverConfigOption {
	return func(resolver *Resolver) error {
		clientResolver, err := clientcredentials.NewResolver(options...)
		if err != nil {
			return err
		}
		resolver.clientResolver = clientResolver
		return nil
	}
}
