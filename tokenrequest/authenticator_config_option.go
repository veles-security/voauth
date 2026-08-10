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

// WithAuthenticatorClientArtifactAuthenticator configures the optional
// authenticator for the client credentials artifact carried by the token request.
func WithAuthenticatorClientArtifactAuthenticator(authenticator vapi.ArtifactAuthenticator[*clientcredentials.ClientCredentials, clientcredentials.ArtifactAuthenticatorOption]) AuthenticatorConfigOption {
	return func(tokenRequestAuthenticator *Authenticator) error {
		if authenticator == nil {
			return errors.New("nil client credentials authenticator")
		}
		tokenRequestAuthenticator.clientArtifactAuthenticator = authenticator
		return nil
	}
}

// WithAuthenticatorClientArtifactAuthenticatorOptions constructs the optional
// client artifact authenticator with the provided configuration options.
func WithAuthenticatorClientArtifactAuthenticatorOptions(options ...clientcredentials.ArtifactAuthenticatorConfigOption) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		clientAuthenticator, err := clientcredentials.NewArtifactAuthenticator(options...)
		if err != nil {
			return err
		}
		authenticator.clientArtifactAuthenticator = clientAuthenticator
		return nil
	}
}
