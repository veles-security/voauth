package tokenresponse

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithValidatorAccessTokenValidator configures access token validation.
func WithValidatorAccessTokenValidator(validator token.AnyTokenValidator) ValidatorConfigOption {
	return func(target *Validator) error {
		if validator == nil {
			return errors.New("nil access token validator")
		}
		target.accessTokenValidator = validator
		return nil
	}
}

// WithValidatorAccessTokenValidatorOptions constructs the access token validator.
func WithValidatorAccessTokenValidatorOptions(options ...jwt.ValidatorConfigOption) ValidatorConfigOption {
	return func(target *Validator) error {
		validator, err := jwt.NewValidator(options...)
		if err != nil {
			return err
		}
		target.accessTokenValidator = validator
		return nil
	}
}

// WithValidatorRefreshTokenValidator configures refresh token validation.
func WithValidatorRefreshTokenValidator(validator token.AnyTokenValidator) ValidatorConfigOption {
	return func(target *Validator) error {
		if validator == nil {
			return errors.New("nil refresh token validator")
		}
		target.refreshTokenValidator = validator
		return nil
	}
}

// WithValidatorRefreshTokenValidatorOptions constructs the refresh token validator.
func WithValidatorRefreshTokenValidatorOptions(options ...jwt.ValidatorConfigOption) ValidatorConfigOption {
	return func(target *Validator) error {
		validator, err := jwt.NewValidator(options...)
		if err != nil {
			return err
		}
		target.refreshTokenValidator = validator
		return nil
	}
}

// WithValidatorIDTokenValidator configures ID token validation.
func WithValidatorIDTokenValidator(validator token.AnyTokenValidator) ValidatorConfigOption {
	return func(target *Validator) error {
		if validator == nil {
			return errors.New("nil ID token validator")
		}
		target.idTokenValidator = validator
		return nil
	}
}

// WithValidatorIDTokenValidatorOptions constructs the ID token validator.
func WithValidatorIDTokenValidatorOptions(options ...jwt.ValidatorConfigOption) ValidatorConfigOption {
	return func(target *Validator) error {
		validator, err := jwt.NewValidator(options...)
		if err != nil {
			return err
		}
		target.idTokenValidator = validator
		return nil
	}
}

// WithValidatorAllowedTokenTypes configures accepted token_type values case-insensitively.
func WithValidatorAllowedTokenTypes(tokenTypes ...string) ValidatorConfigOption {
	return func(target *Validator) error {
		if len(tokenTypes) == 0 {
			return errors.New("no allowed token types")
		}
		allowed := make(map[string]struct{}, len(tokenTypes))
		for index, tokenType := range tokenTypes {
			if tokenType == "" {
				return fmt.Errorf("empty allowed token type at index %d", index)
			}
			allowed[strings.ToLower(tokenType)] = struct{}{}
		}
		target.allowedTokenTypes = allowed
		return nil
	}
}

// WithValidatorAllowedIssuedTokenTypes configures accepted RFC 8693 issued token type URIs.
func WithValidatorAllowedIssuedTokenTypes(tokenTypes ...string) ValidatorConfigOption {
	return func(target *Validator) error {
		if len(tokenTypes) == 0 {
			return errors.New("no allowed issued token types")
		}
		allowed := make(map[string]struct{}, len(tokenTypes))
		for index, tokenType := range tokenTypes {
			parsed, err := url.Parse(tokenType)
			if err != nil || !parsed.IsAbs() {
				return fmt.Errorf("invalid allowed issued token type %q at index %d", tokenType, index)
			}
			allowed[tokenType] = struct{}{}
		}
		target.allowedIssuedTypes = allowed
		return nil
	}
}

// WithValidatorRequireAccessToken controls whether an access token is required.
func WithValidatorRequireAccessToken(required bool) ValidatorConfigOption {
	return func(target *Validator) error {
		target.requireAccessToken = required
		return nil
	}
}

// WithValidatorAllowIDToken controls whether an ID token is permitted.
func WithValidatorAllowIDToken(allowed bool) ValidatorConfigOption {
	return func(target *Validator) error {
		target.allowIDToken = allowed
		return nil
	}
}

// WithValidatorRequireIDToken controls whether an ID token is required.
func WithValidatorRequireIDToken(required bool) ValidatorConfigOption {
	return func(target *Validator) error {
		target.requireIDToken = required
		return nil
	}
}

// WithValidatorRequireIssuedTokenType enables the RFC 8693 response requirement.
func WithValidatorRequireIssuedTokenType(required bool) ValidatorConfigOption {
	return func(target *Validator) error {
		target.requireIssuedType = required
		return nil
	}
}

// WithValidatorRuntimeOptions configures options applied before per-call options.
func WithValidatorRuntimeOptions(options ...ValidatorOption) ValidatorConfigOption {
	return func(target *Validator) error {
		target.runtimeOptions = append([]ValidatorOption(nil), options...)
		return nil
	}
}
