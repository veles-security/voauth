package tokenrequest

import (
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

func WithAuthenticatorReader(reader vapi.Reader[*http.Request, *TokenRequest, ReaderOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if reader == nil {
			return errors.New("nil token request reader")
		}
		authenticator.reader = reader
		return nil
	}
}

func WithAuthenticatorReaderOptions(options ...ReaderConfigOption) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		reader, err := NewReader(options...)
		if err != nil {
			return err
		}
		authenticator.reader = reader
		return nil
	}
}

func WithAuthenticatorValidator(validator vapi.Validator[*TokenRequest, ValidatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if validator == nil {
			return errors.New("nil token request validator")
		}
		authenticator.validator = validator
		return nil
	}
}

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

func WithAuthenticatorResolver(resolver vapi.Resolver[*TokenRequest, ResolverOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if resolver == nil {
			return errors.New("nil token request resolver")
		}
		authenticator.resolver = resolver
		return nil
	}
}

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
