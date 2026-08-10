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

// WithAuthenticatorArtifactAuthenticator configures the JWT artifact authenticator.
func WithAuthenticatorArtifactAuthenticator(artifactAuthenticator vapi.ArtifactAuthenticator[*Token, ArtifactAuthenticatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if artifactAuthenticator == nil {
			return errors.New("nil JWT artifact authenticator")
		}
		authenticator.artifactAuthenticator = artifactAuthenticator
		return nil
	}
}

// WithAuthenticatorArtifactAuthenticatorOptions configures the JWT artifact
// authenticator by constructing it with the provided configuration options.
func WithAuthenticatorArtifactAuthenticatorOptions(options ...ArtifactAuthenticatorConfigOption) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		artifactAuthenticator, err := NewArtifactAuthenticator(options...)
		if err != nil {
			return err
		}
		authenticator.artifactAuthenticator = artifactAuthenticator
		return nil
	}
}
