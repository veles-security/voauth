package jwt

import (
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

// WithAuthenticatorReader configures the JWT token reader.
func WithAuthenticatorReader(reader vapi.Reader[*http.Request, *Token, ReaderOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if reader == nil {
			return errors.New("nil JWT token reader")
		}
		authenticator.reader = reader
		return nil
	}
}

// WithAuthenticatorValidator configures the JWT token validator.
func WithAuthenticatorValidator(validator vapi.Validator[*Token, ValidatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if validator == nil {
			return errors.New("nil JWT token validator")
		}
		authenticator.validator = validator
		return nil
	}
}

// WithAuthenticatorValidatorOptions configures the JWT token validator by
// constructing it with the provided validator configuration options.
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

// WithAuthenticatorResolver configures the JWT resolver.
func WithAuthenticatorResolver(resolver vapi.Resolver[*Token, ResolverOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if resolver == nil {
			return errors.New("nil JWT resolver")
		}
		authenticator.resolver = resolver
		return nil
	}
}

// WithAuthenticatorResolverOptions configures the JWT resolver by constructing
// it with the provided configuration options.
func WithAuthenticatorResolverOptions(options ...ResolverConfigOption) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		resolver, err := NewResolver(options...)
		if err != nil {
			return err
		}
		authenticator.resolver = resolver
		return nil
	}
}
