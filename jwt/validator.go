package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/jws"
	"github.com/veles-security/voauth/token"
)

type Validator struct {
	verifier       vapi.Verifier[jws.VerifierOption]
	runtimeOptions []ValidatorOption
}

type ValidatorConfigOption func(*Validator) error

type ValidateFunc func(ctx context.Context, artifact *Token) error

type ValidatorOption func(next ValidateFunc) ValidateFunc

func NewValidator(configOptions ...ValidatorConfigOption) (*Validator, error) {
	validator := &Validator{}
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

// ValidateAnyToken implements [token.AnyTokenValidator].
func (v *Validator) ValidateAnyToken(ctx context.Context, artifact token.AnyToken) error {
	jwtArtifact, ok := artifact.(*Token)
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrNotApplicable, errors.New("not a JWT token"))
	}
	return v.Validate(ctx, jwtArtifact)
}

// Validate implements [vapi.Validator].
func (v *Validator) Validate(ctx context.Context, artifact *Token, options ...ValidatorOption) error {
	if v == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot validate JWT with nil validator"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot validate nil JWT"))
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

func (v *Validator) validate(ctx context.Context, token *Token) error {
	if v.verifier == nil {
		return nil
	}
	header, err := json.Marshal(token.Header)
	if err != nil {
		return err
	}
	return v.verifier.Verify(ctx, header, token.signature)
}

var _ vapi.Validator[*Token, ValidatorOption] = &Validator{}
var _ token.AnyTokenValidator = &Validator{}
