package clientcredentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

type Validator struct {
	allowedMethods map[string]struct{}
}

type ValidatorConfigOption func(*Validator) error

type ValidateFunc func(ctx context.Context, artifact *ClientCredentials) error

type ValidatorOption func(next ValidateFunc) ValidateFunc

func NewValidator(configOptions ...ValidatorConfigOption) (*Validator, error) {
	validator := &Validator{allowedMethods: map[string]struct{}{
		ClientSecretBasicAuthMethod: {},
		ClientSecretPostAuthMethod:  {},
		PrivateKeyJwtAuthMethod:     {},
	}}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil validator config option"))
		}
		if err := option(validator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return validator, nil
}

// Validate implements [vapi.Validator].
func (v *Validator) Validate(ctx context.Context, artifact *ClientCredentials, options ...ValidatorOption) error {
	if v == nil || v.allowedMethods == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot validate client credentials with invalid validator configuration"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot validate nil client credentials"))
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

func (v *Validator) validate(_ context.Context, artifact *ClientCredentials) error {
	if artifact.AuthMethod == "" {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing client authentication method"))
	}
	switch artifact.AuthMethod {
	case ClientSecretBasicAuthMethod, ClientSecretPostAuthMethod, PrivateKeyJwtAuthMethod:
	default:
		return vapi.NewErrorCategory(vapi.ErrUnsupported, fmt.Errorf("unsupported client authentication method %q", artifact.AuthMethod))
	}
	if _, allowed := v.allowedMethods[artifact.AuthMethod]; !allowed {
		return vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("client authentication method %q is not allowed", artifact.AuthMethod))
	}
	if artifact.ClientId == "" {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing client ID"))
	}

	switch artifact.AuthMethod {
	case ClientSecretBasicAuthMethod, ClientSecretPostAuthMethod:
		if artifact.ClientSecret == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing client secret"))
		}
		if artifact.ClientAssertionType != "" || artifact.ClientAssertion != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("client secret credentials contain a client assertion"))
		}
	case PrivateKeyJwtAuthMethod:
		if artifact.ClientSecret != "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("private key JWT credentials contain a client secret"))
		}
		if artifact.ClientAssertionType == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing client assertion type"))
		}
		if artifact.ClientAssertion == nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing client assertion"))
		}
	}

	return nil
}

var _ vapi.Validator[*ClientCredentials, ValidatorOption] = &Validator{}
