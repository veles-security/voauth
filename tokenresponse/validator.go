package tokenresponse

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Validator struct {
	accessTokenValidator  token.AnyTokenValidator
	refreshTokenValidator token.AnyTokenValidator
	idTokenValidator      token.AnyTokenValidator
	allowedTokenTypes     map[string]struct{}
	allowedIssuedTypes    map[string]struct{}
	requireAccessToken    bool
	allowIDToken          bool
	requireIDToken        bool
	requireIssuedType     bool
	runtimeOptions        []ValidatorOption
}

type ValidatorConfigOption func(*Validator) error

type ValidateFunc func(ctx context.Context, artifact *TokenResponse) error

type ValidatorOption func(next ValidateFunc) ValidateFunc

func NewValidator(configOptions ...ValidatorConfigOption) (*Validator, error) {
	validator := &Validator{
		allowedTokenTypes:  map[string]struct{}{"bearer": {}},
		requireAccessToken: true,
		allowIDToken:       true,
	}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil validator config option"))
		}
		if err := option(validator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if validator.requireIDToken && !validator.allowIDToken {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot require ID tokens when ID tokens are not allowed"))
	}
	if validator.accessTokenValidator == nil {
		tokenValidator, err := jwt.NewValidator()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create access token validator: %w", err))
		}
		validator.accessTokenValidator = tokenValidator
	}
	if validator.refreshTokenValidator == nil {
		tokenValidator, err := jwt.NewValidator()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create refresh token validator: %w", err))
		}
		validator.refreshTokenValidator = tokenValidator
	}
	if validator.idTokenValidator == nil {
		tokenValidator, err := jwt.NewValidator()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create ID token validator: %w", err))
		}
		validator.idTokenValidator = tokenValidator
	}
	return validator, nil
}

// Validate implements [vapi.Validator].
func (v *Validator) Validate(ctx context.Context, artifact *TokenResponse, options ...ValidatorOption) error {
	if v == nil || v.accessTokenValidator == nil || v.refreshTokenValidator == nil || v.idTokenValidator == nil || v.allowedTokenTypes == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot validate token response with invalid validator configuration"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot validate nil token response"))
	}

	allOptions := slices.Concat(v.runtimeOptions, options)
	next := v.validate
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
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

func (v *Validator) validate(ctx context.Context, artifact *TokenResponse) error {
	if v.requireAccessToken && artifact.AccessToken == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing access token"))
	}
	if artifact.AccessToken != nil && artifact.TokenType == "" {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing token type"))
	}
	if artifact.TokenType != "" {
		if _, allowed := v.allowedTokenTypes[strings.ToLower(artifact.TokenType)]; !allowed {
			return vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("token type %q is not allowed", artifact.TokenType))
		}
	}
	if artifact.ExpiresIn < 0 {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("negative access token lifetime"))
	}
	if artifact.Scope != "" {
		for _, scope := range strings.Split(artifact.Scope, " ") {
			if scope == "" {
				return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("invalid empty scope"))
			}
			for _, character := range scope {
				if character < 0x21 || character == 0x22 || character == 0x5c || character > 0x7e {
					return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid scope %q", scope))
				}
			}
		}
	}
	if v.requireIssuedType && artifact.IssuedTokenType == "" {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing issued token type"))
	}
	if artifact.IssuedTokenType != "" {
		if artifact.AccessToken == nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("issued token type without issued access token field"))
		}
		issuedType, err := url.Parse(artifact.IssuedTokenType)
		if err != nil || !issuedType.IsAbs() {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid issued token type %q", artifact.IssuedTokenType))
		}
		if v.allowedIssuedTypes != nil {
			if _, allowed := v.allowedIssuedTypes[artifact.IssuedTokenType]; !allowed {
				return vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("issued token type %q is not allowed", artifact.IssuedTokenType))
			}
		}
	}
	if artifact.IdToken != nil && !v.allowIDToken {
		return vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("ID token is not allowed"))
	}
	if artifact.IdToken == nil && v.requireIDToken {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing ID token"))
	}
	if artifact.AccessToken != nil {
		if err := v.accessTokenValidator.ValidateAnyToken(ctx, artifact.AccessToken); err != nil {
			return fmt.Errorf("validate access token: %w", err)
		}
	}
	if artifact.RefreshToken != nil {
		if err := v.refreshTokenValidator.ValidateAnyToken(ctx, artifact.RefreshToken); err != nil {
			return fmt.Errorf("validate refresh token: %w", err)
		}
	}
	if artifact.IdToken != nil {
		if err := v.idTokenValidator.ValidateAnyToken(ctx, artifact.IdToken); err != nil {
			return fmt.Errorf("validate ID token: %w", err)
		}
	}
	return nil
}

var _ vapi.Validator[*TokenResponse, ValidatorOption] = &Validator{}
