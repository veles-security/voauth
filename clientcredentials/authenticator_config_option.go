package clientcredentials

import (
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

// WithAuthenticatorAuthCallback configures the callback for a client
// authentication method. It may be provided repeatedly for different methods.
func WithAuthenticatorAuthCallback(method string, callback AuthCallback) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if method == "" {
			return errors.New("empty client authentication method")
		}
		if callback == nil {
			return fmt.Errorf("nil authentication callback for client authentication method %q", method)
		}
		authenticator.authCallbacks[method] = callback
		return nil
	}
}

// WithAuthenticatorValidator configures the optional client credentials validator.
func WithAuthenticatorValidator(validator vapi.Validator[*ClientCredentials, ValidatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if validator == nil {
			return errors.New("nil client credentials validator")
		}
		authenticator.validator = validator
		return nil
	}
}

// WithAuthenticatorValidatorOptions constructs the optional client credentials
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
