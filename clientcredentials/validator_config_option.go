package clientcredentials

import (
	"errors"
	"fmt"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithValidatorTokenValidator configures the validator used for client assertions.
func WithValidatorTokenValidator(validator token.AnyTokenValidator) ValidatorConfigOption {
	return func(credentialsValidator *Validator) error {
		if validator == nil {
			return errors.New("nil token validator")
		}
		credentialsValidator.tokenValidator = validator
		return nil
	}
}

// WithValidatorTokenValidatorOptions constructs the JWT validator used for client assertions.
func WithValidatorTokenValidatorOptions(options ...jwt.ValidatorConfigOption) ValidatorConfigOption {
	return func(credentialsValidator *Validator) error {
		validator, err := jwt.NewValidator(options...)
		if err != nil {
			return err
		}
		credentialsValidator.tokenValidator = validator
		return nil
	}
}

// WithValidatorAllowedMethods restricts the client authentication methods accepted by a Validator.
func WithValidatorAllowedMethods(methods ...string) ValidatorConfigOption {
	return func(validator *Validator) error {
		if len(methods) == 0 {
			return errors.New("no allowed client authentication methods")
		}

		allowed := make(map[string]struct{}, len(methods))
		for index, method := range methods {
			switch method {
			case ClientSecretBasicAuthMethod, ClientSecretPostAuthMethod, PrivateKeyJwtAuthMethod:
				allowed[method] = struct{}{}
			default:
				return fmt.Errorf("unsupported allowed client authentication method %q at index %d", method, index)
			}
		}
		validator.allowedMethods = allowed
		return nil
	}
}
