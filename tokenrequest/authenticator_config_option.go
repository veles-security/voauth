package tokenrequest

import (
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

// WithAuthenticatorAuthCallback configures the callback for an OAuth grant
// type. It may be provided repeatedly for different grant types.
func WithAuthenticatorAuthCallback(grantType string, callback AuthCallback) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if grantType == "" {
			return errors.New("empty grant type")
		}
		if callback == nil {
			return fmt.Errorf("nil authentication callback for grant type %q", grantType)
		}
		authenticator.authCallbacks[grantType] = callback
		return nil
	}
}

// WithAuthenticatorValidator configures the optional token request validator.
func WithAuthenticatorValidator(validator vapi.Validator[*TokenRequest, ValidatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if validator == nil {
			return errors.New("nil token request validator")
		}
		authenticator.validator = validator
		return nil
	}
}

// WithAuthenticatorValidatorOptions constructs the optional token request
// validator with the provided configuration options.
func WithAuthenticatorValidatorOptions(options ...ValidatorConfigOption) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		validator, err := NewValidator(options...)
		if err != nil {
			return err
		}
		authenticator.validator = validator
		return nil
	}
}

// WithAuthenticatorClientResolver configures the optional
// authenticator for the client credentials artifact carried by the token request.
func WithAuthenticatorClientResolver(resolver vapi.Resolver[*clientcredentials.ClientCredentials, clientcredentials.ResolverOption]) AuthenticatorConfigOption {
	return func(tokenRequestAuthenticator *Authenticator) error {
		if resolver == nil {
			return errors.New("nil client credentials resolver")
		}
		tokenRequestAuthenticator.clientResolver = resolver
		return nil
	}
}

// WithAuthenticatorClientResolverOptions constructs the optional
// client resolver with the provided configuration options.
func WithAuthenticatorClientResolverOptions(options ...clientcredentials.ResolverConfigOption) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		clientResolver, err := clientcredentials.NewResolver(options...)
		if err != nil {
			return err
		}
		authenticator.clientResolver = clientResolver
		return nil
	}
}
