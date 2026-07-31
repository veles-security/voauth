package voauth

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

type JwtValidationPolicer interface {
	Validate(context.Context, *JwtToken) error
}

type jwtValidationPolicyFunc func(context.Context, *JwtToken) error

func (f jwtValidationPolicyFunc) Validate(ctx context.Context, token *JwtToken) error {
	return f(ctx, token)
}

// ----------------------------------------------------------------------------

type JwtSignatureValidationPolicy struct {
	Kid string
	Alg sig.SigAlg
	Key crypto.PublicKey
}

// Validate implements [JwtValidationPolicer].
func (j *JwtSignatureValidationPolicy) Validate(_ context.Context, token *JwtToken) error {

	return nil
}

// ----------------------------------------------------------------------------

func WithType(tokenType string) JwtValidationPolicer {
	return &JwtTypeValidationPolicy{Type: tokenType}
}

type JwtTypeValidationPolicy struct {
	Type string
}

// Validate implements [JwtValidationPolicer].
func (p *JwtTypeValidationPolicy) Validate(_ context.Context, token *JwtToken) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("nil JWT"))
	}
	if token.Header["typ"] != p.Type {
		return vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("JWT has the wrong type"))
	}
	return nil
}

// ----------------------------------------------------------------------------

func WithNonce(nonce string) JwtValidationPolicer {
	return &JwtNonceValidationPolicy{Nonce: nonce}
}

type JwtNonceValidationPolicy struct {
	Nonce string
}

// Validate implements [JwtValidationPolicer].
func (p *JwtNonceValidationPolicy) Validate(ctx context.Context, token *JwtToken) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("nil JWT"))
	}

	nonce, ok := token.Claims["nonce"]
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrBinding, fmt.Errorf("JWT nonce is missing"))
	}
	value, ok := nonce.(string)
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must be a string", "nonce"))
	}
	if subtle.ConstantTimeCompare([]byte(value), []byte(p.Nonce)) != 1 {
		return vapi.NewErrorCategory(vapi.ErrBinding, fmt.Errorf("JWT has the wrong nonce"))
	}
	return nil
}

// ----------------------------------------------------------------------------

func WithValidIssuer(issuer string) JwtValidationPolicer {
	return &JwtIssuerValidationPolicy{Issuer: issuer}
}

type JwtIssuerValidationPolicy struct {
	Issuer string
}

// Validate implements [JwtValidationPolicer].
func (p *JwtIssuerValidationPolicy) Validate(ctx context.Context, token *JwtToken) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("nil JWT"))
	}

	issuer, ok := token.Claims["iss"]
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrWrongIssuer, fmt.Errorf("JWT issuer is missing"))
	}
	value, ok := issuer.(string)
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must be a string", "iss"))
	}
	if value != p.Issuer {
		return vapi.NewErrorCategory(vapi.ErrWrongIssuer, fmt.Errorf("JWT has the wrong issuer"))
	}
	return nil
}

// ----------------------------------------------------------------------------

func WithValidAudience(audiences ...string) JwtValidationPolicer {
	return &JwtAudienceValidationPolicy{Audiences: audiences}
}

type JwtAudienceValidationPolicy struct {
	Audience  string
	Audiences []string
}

// Validate implements [JwtValidationPolicer].
func (p *JwtAudienceValidationPolicy) Validate(ctx context.Context, token *JwtToken) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("nil JWT"))
	}

	audience, ok := token.Claims["aud"]
	if !ok {
		return vapi.NewErrorCategory(vapi.ErrWrongAudience, fmt.Errorf("JWT audience is missing"))
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
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must not be empty", "aud"))
		}
		if matches(value) {
			return nil
		}
	case []any:
		if len(value) == 0 {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must not be empty", "aud"))
		}
		matched := false
		for _, item := range value {
			text, ok := item.(string)
			if !ok || text == "" {
				return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must contain only strings", "aud"))
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
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must not be empty", "aud"))
		}
		matched := false
		for _, item := range value {
			if item == "" {
				return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must contain only strings", "aud"))
			}
			if matches(item) {
				matched = true
			}
		}
		if matched {
			return nil
		}
	default:
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("JWT claim %q must be a string or an array of strings", "aud"))
	}
	return vapi.NewErrorCategory(vapi.ErrWrongAudience, fmt.Errorf("JWT has the wrong audience"))
}

// ----------------------------------------------------------------------------

func WithValidClock(leeway time.Duration) JwtValidationPolicer {
	return &JwtClockValidationPolicy{Leeway: leeway}
}

type JwtClockValidationPolicy struct {
	Leeway time.Duration
}

// Validate implements [JwtValidationPolicer].
func (p *JwtClockValidationPolicy) Validate(ctx context.Context, token *JwtToken) error {
	if token == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("nil JWT"))
	}

	now := float64(time.Now().UnixNano()) / float64(time.Second)
	if exp, ok, err := p.numericDate(token.Claims, "exp"); err != nil {
		return err
	} else if ok && now >= exp+p.Leeway.Seconds() {
		return vapi.NewErrorCategory(vapi.ErrExpired, fmt.Errorf("JWT expired"))
	}
	if nbf, ok, err := p.numericDate(token.Claims, "nbf"); err != nil {
		return err
	} else if ok && now+p.Leeway.Seconds() < nbf {
		return vapi.NewErrorCategory(vapi.ErrNotYetValid, fmt.Errorf("JWT is not valid yet"))
	}
	return nil
}

func (p *JwtClockValidationPolicy) numericDate(claims map[string]any, name string) (float64, bool, error) {
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
	Policies []JwtValidationPolicer
}

func NewJwtValidator(policies ...JwtValidationPolicer) *JwtValidator {
	validator := &JwtValidator{
		Policies: []JwtValidationPolicer{},
	}
	for _, policy := range policies {
		validator.Policies = append(validator.Policies, policy)
	}
	return validator
}

// Validate implements [vapi.ValidationSchemer].
func (j *JwtValidator) Validate(ctx context.Context, token *JwtToken, policies ...JwtValidationPolicer) error {
	validate := func(ps []JwtValidationPolicer) error {
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

var _ vapi.Validator[*JwtToken, JwtValidationPolicer] = &JwtValidator{}
var _ JwtValidationPolicer = &JwtIssuerValidationPolicy{}
var _ JwtValidationPolicer = &JwtAudienceValidationPolicy{}
var _ JwtValidationPolicer = &JwtClockValidationPolicy{}
var _ JwtValidationPolicer = &JwtSignatureValidationPolicy{}
var _ JwtValidationPolicer = &JwtTypeValidationPolicy{}
var _ JwtValidationPolicer = &JwtNonceValidationPolicy{}
