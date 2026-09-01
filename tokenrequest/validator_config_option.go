package tokenrequest

import (
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithValidatorRefreshTokenValidator configures the validator used for refresh tokens.
func WithValidatorRefreshTokenValidator(validator token.AnyTokenValidator) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		if validator == nil {
			return errors.New("nil refresh token validator")
		}
		tokenRequestValidator.refreshTokenValidator = validator
		return nil
	}
}

// WithValidatorRefreshTokenValidatorOptions constructs the JWT validator used for refresh tokens.
func WithValidatorRefreshTokenValidatorOptions(options ...jwt.ValidatorConfigOption) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		validator, err := jwt.NewValidator(options...)
		if err != nil {
			return err
		}
		tokenRequestValidator.refreshTokenValidator = validator
		return nil
	}
}

// WithValidatorAssertionTokenValidator configures the validator used for JWT and SAML bearer assertions.
func WithValidatorAssertionTokenValidator(validator token.AnyTokenValidator) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		if validator == nil {
			return errors.New("nil assertion token validator")
		}
		tokenRequestValidator.assertionTokenValidator = validator
		return nil
	}
}

// WithValidatorAssertionTokenValidatorOptions constructs the JWT validator used for JWT and SAML bearer assertions.
func WithValidatorAssertionTokenValidatorOptions(options ...jwt.ValidatorConfigOption) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		validator, err := jwt.NewValidator(options...)
		if err != nil {
			return err
		}
		tokenRequestValidator.assertionTokenValidator = validator
		return nil
	}
}

// WithValidatorAllowedGrantTypes restricts the OAuth grant types accepted by a Validator.
func WithValidatorAllowedGrantTypes(grantTypes ...string) ValidatorConfigOption {
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

// WithValidatorAllowedScopes restricts requested OAuth scopes. An unset scope remains valid.
func WithValidatorAllowedScopes(scopes ...string) ValidatorConfigOption {
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

// WithValidatorClientCredentialsValidator sets the validator used for the request's client credentials.
func WithValidatorClientCredentialsValidator(validator vapi.Validator[*clientcredentials.ClientCredentials, clientcredentials.ValidatorOption]) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		if validator == nil {
			return errors.New("nil client credentials validator")
		}
		tokenRequestValidator.clientCredentialsValidator = validator
		return nil
	}
}

// WithValidatorClientCredentialsValidatorOptions constructs the client credentials validator.
func WithValidatorClientCredentialsValidatorOptions(options ...clientcredentials.ValidatorConfigOption) ValidatorConfigOption {
	return func(tokenRequestValidator *Validator) error {
		validator, err := clientcredentials.NewValidator(options...)
		if err != nil {
			return err
		}
		tokenRequestValidator.clientCredentialsValidator = validator
		return nil
	}
}

// WithValidatorRuntimeOptions configures validator options applied to every
// Validate call before its per-call options.
func WithValidatorRuntimeOptions(options ...ValidatorOption) ValidatorConfigOption {
	return func(validator *Validator) error {
		validator.runtimeOptions = append([]ValidatorOption(nil), options...)
		return nil
	}
}
