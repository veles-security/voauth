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

// WithAuthenticatorExtractor configures the JWT principal extractor.
func WithAuthenticatorExtractor(extractor vapi.PrincipalExtractor[*Token, JwtPrincipalMapper]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if extractor == nil {
			return errors.New("nil JWT principal extractor")
		}
		authenticator.extractor = extractor
		return nil
	}
}
