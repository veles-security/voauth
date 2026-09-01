// Package presets provides convenient, opinionated compositions of token
// endpoint components. The lower-level tokenendpoint options remain available
// when callers need to replace individual components.
package presets

import (
	"errors"
	"fmt"

	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenrequest"
)

// AuthenticatorOption configures the standard token-request authenticator
// assembled by [Authenticator].
type AuthenticatorOption func(*authenticatorConfig) error

type authenticatorConfig struct {
	grantTypes            []string
	clientMethods         []string
	clientResolverOptions []clientcredentials.ResolverOption
	subjectResolver       tokenrequest.ResolveFunc
}

// Authenticator assembles the standard token-request validator and resolver.
func Authenticator(options ...AuthenticatorOption) tokenendpoint.TokenEndpointConfigOption {
	return func(endpoint *tokenendpoint.TokenEndpoint) error {
		config := &authenticatorConfig{}
		for index, option := range options {
			if option == nil {
				return fmt.Errorf("nil authenticator preset option at index %d", index)
			}
			if err := option(config); err != nil {
				return err
			}
		}

		validatorOptions := make([]tokenrequest.ValidatorConfigOption, 0, 2)
		if len(config.grantTypes) > 0 {
			validatorOptions = append(validatorOptions, tokenrequest.WithValidatorAllowedGrantTypes(config.grantTypes...))
		}
		if len(config.clientMethods) > 0 {
			validatorOptions = append(validatorOptions, tokenrequest.WithValidatorClientCredentialsValidatorOptions(
				clientcredentials.WithValidatorAllowedMethods(config.clientMethods...),
			))
		}

		resolverOptions := make([]tokenrequest.ResolverConfigOption, 0, 2)
		if len(config.clientResolverOptions) > 0 {
			resolverOptions = append(resolverOptions, tokenrequest.WithResolverClientResolverOptions(
				clientcredentials.WithResolverRuntimeOptions(config.clientResolverOptions...),
			))
		}
		if config.subjectResolver != nil {
			resolverOptions = append(resolverOptions, tokenrequest.WithResolverRuntimeOptions(
				tokenrequest.WithResolveFunc(config.subjectResolver),
			))
		}

		return tokenendpoint.WithTokenRequestAuthenticatorOptions(
			tokenrequest.WithAuthenticatorValidatorOptions(validatorOptions...),
			tokenrequest.WithAuthenticatorResolverOptions(resolverOptions...),
		)(endpoint)
	}
}

// GrantTypes restricts the grant types accepted by the token endpoint.
func GrantTypes(grantTypes ...string) AuthenticatorOption {
	return func(config *authenticatorConfig) error {
		config.grantTypes = append([]string(nil), grantTypes...)
		return nil
	}
}

// ClientAuthentication enables a client authentication method and associates
// it with the callback that authenticates credentials using that method.
// It may be supplied more than once to support multiple methods.
func ClientAuthentication(method string, authenticate clientcredentials.ResolveFunc) AuthenticatorOption {
	return func(config *authenticatorConfig) error {
		if authenticate == nil {
			return errors.New("nil client authentication callback")
		}
		config.clientMethods = append(config.clientMethods, method)
		config.clientResolverOptions = append(config.clientResolverOptions,
			clientcredentials.WithResolverAuthenticationMethod(method, authenticate))
		return nil
	}
}

// ResolveSubject sets the callback that resolves the token subject after the
// client has been authenticated.
func ResolveSubject(resolve tokenrequest.ResolveFunc) AuthenticatorOption {
	return func(config *authenticatorConfig) error {
		if resolve == nil {
			return errors.New("nil subject resolver")
		}
		config.subjectResolver = resolve
		return nil
	}
}
