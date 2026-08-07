package clientcredentials

import (
	"errors"
	"fmt"
)

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
