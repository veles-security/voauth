package tokenrequest

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

type Validator struct {
	allowedGrantTypes          map[string]struct{}
	allowedScopes              map[string]struct{}
	clientCredentialsValidator vapi.Validator[*clientcredentials.ClientCredentials, clientcredentials.ValidatorOption]
}

type ValidatorConfigOption func(*Validator) error

type ValidateFunc func(ctx context.Context, artifact *TokenRequest) error

type ValidatorOption func(next ValidateFunc) ValidateFunc

func NewValidator(configOptions ...ValidatorConfigOption) (*Validator, error) {
	validator := &Validator{allowedGrantTypes: map[string]struct{}{
		AuthorizationCodeGrantType: {},
		PasswordGrantType:          {},
		ClientCredentialsGrantType: {},
		RefreshTokenGrantType:      {},
		DeviceCodeGrantType:        {},
		JwtBearerGrantType:         {},
		Saml2BearerGrantType:       {},
	}}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil validator config option"))
		}
		if err := option(validator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if validator.clientCredentialsValidator == nil {
		credentialsValidator, err := clientcredentials.NewValidator()
		if err != nil {
			return nil, err
		}
		validator.clientCredentialsValidator = credentialsValidator
	}
	return validator, nil
}

// Validate implements [vapi.Validator].
func (v *Validator) Validate(ctx context.Context, artifact *TokenRequest, options ...ValidatorOption) error {
	if v == nil || v.allowedGrantTypes == nil || v.clientCredentialsValidator == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot validate token request with invalid validator configuration"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot validate nil token request"))
	}

	next := v.validate
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
		if option == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil validator option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("validator option at index %d returned nil ValidateFunc", index))
		}
		next = wrapped
	}
	return next(ctx, artifact)
}

func (v *Validator) validate(ctx context.Context, artifact *TokenRequest) error {
	if artifact.GrantType == "" {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing grant type"))
	}
	switch artifact.GrantType {
	case AuthorizationCodeGrantType, PasswordGrantType, ClientCredentialsGrantType, RefreshTokenGrantType,
		DeviceCodeGrantType, JwtBearerGrantType, Saml2BearerGrantType:
	default:
		return vapi.NewErrorCategory(vapi.ErrUnsupported, fmt.Errorf("unsupported grant type %q", artifact.GrantType))
	}
	if _, allowed := v.allowedGrantTypes[artifact.GrantType]; !allowed {
		return vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("grant type %q is not allowed", artifact.GrantType))
	}

	if err := v.clientCredentialsValidator.Validate(ctx, &artifact.ClientCredentials); err != nil {
		return fmt.Errorf("validate client credentials: %w", err)
	}

	if artifact.Scope != "" {
		for _, scope := range strings.Split(artifact.Scope, " ") {
			if !validScope(scope) {
				return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid scope %q", scope))
			}
			if v.allowedScopes == nil {
				continue
			}
			if _, allowed := v.allowedScopes[scope]; !allowed {
				return vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("scope %q is not allowed", scope))
			}
		}
	}

	switch artifact.GrantType {
	case AuthorizationCodeGrantType:
		if artifact.Code == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing authorization code"))
		}
	case PasswordGrantType:
		if artifact.Username == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing username"))
		}
		if artifact.Password == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing password"))
		}
	case RefreshTokenGrantType:
		if artifact.RefreshToken == nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing refresh token"))
		}
	case DeviceCodeGrantType:
		if artifact.DeviceCode == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing device code"))
		}
	case JwtBearerGrantType, Saml2BearerGrantType:
		if artifact.Assertion == nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing bearer assertion"))
		}
	}

	return nil
}

func validScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, character := range scope {
		if character < 0x21 || character == 0x22 || character == 0x5c || character > 0x7e {
			return false
		}
	}
	return true
}

var _ vapi.Validator[*TokenRequest, ValidatorOption] = &Validator{}
