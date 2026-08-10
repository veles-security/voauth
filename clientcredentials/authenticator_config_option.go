package clientcredentials

import (
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

func WithAuthenticatorReader(reader vapi.Reader[*http.Request, *ClientCredentials, ReaderOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if reader == nil {
			return errors.New("nil client credentials reader")
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

func WithAuthenticatorValidator(validator vapi.Validator[*ClientCredentials, ValidatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if validator == nil {
			return errors.New("nil client credentials validator")
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

func WithAuthenticatorArtifactAuthenticator(artifactAuthenticator vapi.ArtifactAuthenticator[*ClientCredentials, ArtifactAuthenticatorOption]) AuthenticatorConfigOption {
	return func(authenticator *Authenticator) error {
		if artifactAuthenticator == nil {
			return errors.New("nil client credentials artifact authenticator")
		}
		authenticator.artifactAuthenticator = artifactAuthenticator
		return nil
	}
}

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
