package tokenrequest

import (
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

// WithAllowedGrantTypes restricts the OAuth grant types accepted by a Validator.
func WithAllowedGrantTypes(grantTypes ...string) ValidatorConfigOption {
	return func(validator *Validator) error {
		if len(grantTypes) == 0 {
			return errors.New("no allowed grant types")
		}

		allowed := make(map[string]struct{}, len(grantTypes))
		for index, grantType := range grantTypes {
			switch grantType {
			case AuthorizationCodeGrantType, PasswordGrantType, ClientCredentialsGrantType, RefreshTokenGrantType,
				DeviceCodeGrantType, JwtBearerGrantType, Saml2BearerGrantType:
				allowed[grantType] = struct{}{}
			default:
				return fmt.Errorf("unsupported allowed grant type %q at index %d", grantType, index)
			}
		}
		validator.allowedGrantTypes = allowed
		return nil
	}
}

// WithAllowedScopes restricts requested OAuth scopes. An unset scope remains valid.
func WithAllowedScopes(scopes ...string) ValidatorConfigOption {
	return func(validator *Validator) error {
		if len(scopes) == 0 {
			return errors.New("no allowed scopes")
		}

		allowed := make(map[string]struct{}, len(scopes))
		for index, scope := range scopes {
			if !validScope(scope) {
				return fmt.Errorf("invalid allowed scope %q at index %d", scope, index)
			}
			allowed[scope] = struct{}{}
		}
		validator.allowedScopes = allowed
		return nil
	}
}

// WithClientCredentialsValidator sets the validator used for the request's client credentials.
func WithClientCredentialsValidator(validator vapi.Validator[*clientcredentials.ClientCredentials, clientcredentials.ValidatorOption]) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		if validator == nil {
			return errors.New("nil client credentials validator")
		}
		tokenRequestValidator.clientCredentialsValidator = validator
		return nil
	}
}

func WithClientCredentialsValidatoOptions(options ...clientcredentials.ValidatorConfigOption) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		validator, err := clientcredentials.NewValidator(options...)
		if err != nil {
			return err
		}
		tokenRequestValidator.clientCredentialsValidator = validator
		return nil
	}
}
