package jwt

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

type ValidationPolicer interface {
	Validate(context.Context, *Token) error
}

type validationPolicyFunc func(context.Context, *Token) error

func (f validationPolicyFunc) Validate(ctx context.Context, token *Token) error {
	return f(ctx, token)
}

// ----------------------------------------------------------------------------

type SignatureValidationPolicy struct {
	Kid string
	Alg sig.SigAlg
	Key crypto.PublicKey
}

// Validate implements [ValidationPolicer].
func (j *SignatureValidationPolicy) Validate(_ context.Context, token *Token) error {

	return nil
}

// ----------------------------------------------------------------------------

func WithType(tokenType string) ValidationPolicer {
	return &TypeValidationPolicy{Type: tokenType}
}

type TypeValidationPolicy struct {
	Type string
}

// Validate implements [ValidationPolicer].
func (p *TypeValidationPolicy) Validate(_ context.Context, token *Token) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("nil JWT"))
	}
	if token.Header["typ"] != p.Type {
		return vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("JWT has the wrong type"))
	}
	return nil
}

// ----------------------------------------------------------------------------

func WithNonce(nonce string) ValidationPolicer {
	return &NonceValidationPolicy{Nonce: nonce}
}

type NonceValidationPolicy struct {
	Nonce string
}

// Validate implements [ValidationPolicer].
func (p *NonceValidationPolicy) Validate(ctx context.Context, token *Token) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("nil JWT"))
	}

	nonce, ok := token.Claims["nonce"]
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrBinding, errors.New("JWT nonce is missing"))
	}
	value, ok := nonce.(string)
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'nonce' must be a string"))
	}
	if subtle.ConstantTimeCompare([]byte(value), []byte(p.Nonce)) != 1 {
		return vapi.NewErrorCategory(vapi.ErrBinding, errors.New("JWT has the wrong nonce"))
	}
	return nil
}

// ----------------------------------------------------------------------------

func WithValidIssuer(issuer string) ValidationPolicer {
	return &JwtIssuerValidationPolicy{Issuer: issuer}
}

type JwtIssuerValidationPolicy struct {
	Issuer string
}

// Validate implements [ValidationPolicer].
func (p *JwtIssuerValidationPolicy) Validate(ctx context.Context, token *Token) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("nil JWT"))
	}

	issuer, ok := token.Claims["iss"]
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrWrongIssuer, errors.New("JWT issuer is missing"))
	}
	value, ok := issuer.(string)
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'iss' must be a string"))
	}
	if value != p.Issuer {
		return vapi.NewErrorCategory(vapi.ErrWrongIssuer, errors.New("JWT has the wrong issuer"))
	}
	return nil
}

// ----------------------------------------------------------------------------

func WithValidAudience(audiences ...string) ValidationPolicer {
	return &AudienceValidationPolicy{Audiences: audiences}
}

type AudienceValidationPolicy struct {
	Audience  string
	Audiences []string
}

// Validate implements [ValidationPolicer].
func (p *AudienceValidationPolicy) Validate(ctx context.Context, token *Token) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("nil JWT"))
	}

	audience, ok := token.Claims["aud"]
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrWrongAudience, errors.New("JWT audience is missing"))
	}
	matches := func(value string) bool {
		if value == p.Audience {
			return true
		}
		for _, expected := range p.Audiences {
			if value == expected {
				return true
			}
		}
		return false
	}
	switch value := audience.(type) {
	case string:
		if value == "" {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must not be empty"))
		}
		if matches(value) {
			return nil
		}
	case []any:
		if len(value) == 0 {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must not be empty"))
		}
		matched := false
		for _, item := range value {
			text, ok := item.(string)
			if !ok || text == "" {
				return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must contain only strings"))
			}
			if matches(text) {
				matched = true
			}
		}
		if matched {
			return nil
		}
	case []string:
		if len(value) == 0 {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must not be empty"))
		}
		matched := false
		for _, item := range value {
			if item == "" {
				return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must contain only strings"))
			}
			if matches(item) {
				matched = true
			}
		}
		if matched {
			return nil
		}
	default:
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must be a string or an array of strings"))
	}
	return vapi.NewErrorCategory(vapi.ErrWrongAudience, errors.New("JWT has the wrong audience"))
}

// ----------------------------------------------------------------------------

func WithValidClock(leeway time.Duration) ValidationPolicer {
	return &ClockValidationPolicy{Leeway: leeway}
}

type ClockValidationPolicy struct {
	Leeway time.Duration
}

// Validate implements [ValidationPolicer].
func (p *ClockValidationPolicy) Validate(ctx context.Context, token *Token) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("nil JWT"))
	}

	now := float64(time.Now().UnixNano()) / float64(time.Second)
	if exp, ok, err := p.numericDate(token.Claims, "exp"); err != nil {
		return err
	} else if ok && now >= exp+p.Leeway.Seconds() {
		return vapi.NewErrorCategory(vapi.ErrExpired, errors.New("JWT expired"))
	}
	if nbf, ok, err := p.numericDate(token.Claims, "nbf"); err != nil {
		return err
	} else if ok && now+p.Leeway.Seconds() < nbf {
		return vapi.NewErrorCategory(vapi.ErrNotYetValid, errors.New("JWT is not valid yet"))
	}
	return nil
}

func (p *ClockValidationPolicy) numericDate(claims map[string]any, name string) (float64, bool, error) {
	value, ok := claims[name]
	if !ok {
		return 0, false, nil
	}

	switch value := value.(type) {
	case float64:
		return value, true, nil
	case json.Number:
		number, err := value.Float64()
		if err == nil {
			return number, true, nil
		}
	}
	return 0, false, vapi.NewErrorCategory(
		vapi.ErrMalformed,
		fmt.Errorf("JWT claim %q must be a numeric date", name),
	)
}

// ----------------------------------------------------------------------------

type JwtValidator struct {
	Policies []ValidationPolicer
}

func NewJwtValidator(policies ...ValidationPolicer) *JwtValidator {
	validator := &JwtValidator{
		Policies: []ValidationPolicer{},
	}
	for _, policy := range policies {
		validator.Policies = append(validator.Policies, policy)
	}
	return validator
}

// Validate implements [vapi.ValidationSchemer].
func (j *JwtValidator) Validate(ctx context.Context, token *Token, policies ...ValidationPolicer) error {
	validate := func(ps []ValidationPolicer) error {
		for _, p := range ps {
			err := p.Validate(ctx, token)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := validate(j.Policies); err != nil {
		return err
	}
	if err := validate(policies); err != nil {
		return err
	}

	return nil
}

// ----------------------------------------------------------------------------

var _ vapi.Validator[*Token, ValidationPolicer] = &JwtValidator{}
var _ ValidationPolicer = &JwtIssuerValidationPolicy{}
var _ ValidationPolicer = &AudienceValidationPolicy{}
var _ ValidationPolicer = &ClockValidationPolicy{}
var _ ValidationPolicer = &SignatureValidationPolicy{}
var _ ValidationPolicer = &TypeValidationPolicy{}
var _ ValidationPolicer = &NonceValidationPolicy{}
