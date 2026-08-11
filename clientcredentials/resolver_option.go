package clientcredentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

// WithResolverAuthenticationMethod authenticates credentials using authenticate when
// their client authentication method matches method.
func WithResolverAuthenticationMethod(method string, authenticate ResolveFunc) ResolverOption {
	return func(next ResolveFunc) ResolveFunc {
		return func(ctx context.Context, credentials *ClientCredentials) (vapi.Principal, error) {
			if credentials.AuthMethod != method {
				return next(ctx, credentials)
			}
			if method == "" {
				return nil, fmt.Errorf("empty client authentication method")
			}
			if authenticate == nil {
				return nil, errors.New("nil client credentials authentication function")
			}
			return authenticate(ctx, credentials)
		}
	}
}

func WithResolveFunc(f ResolveFunc) ResolverOption {
	return func(next ResolveFunc) ResolveFunc {
		return f
	}
}
