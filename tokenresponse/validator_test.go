package tokenresponse

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type tokenValidatorStub struct {
	err error
}

func (v *tokenValidatorStub) ValidateAnyToken(context.Context, token.AnyToken) error {
	return v.err
}

func TestNewValidator(t *testing.T) {
	assertCreated := func(t *testing.T, got *Validator, err error) {
		t.Helper()
		if err != nil || got == nil || got.accessTokenValidator == nil || got.refreshTokenValidator == nil || got.idTokenValidator == nil {
			t.Fatalf("NewValidator() = (%#v, %v), want configured validator", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *Validator, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewValidator() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}

	tests := []struct {
		name    string
		options []ValidatorConfigOption
		assert  func(*testing.T, *Validator, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "direct dependencies", options: []ValidatorConfigOption{WithValidatorAccessTokenValidator(&tokenValidatorStub{}), WithValidatorRefreshTokenValidator(&tokenValidatorStub{}), WithValidatorIDTokenValidator(&tokenValidatorStub{})}, assert: assertCreated},
		{name: "dependency options", options: []ValidatorConfigOption{WithValidatorAccessTokenValidatorOptions(), WithValidatorRefreshTokenValidatorOptions(), WithValidatorIDTokenValidatorOptions()}, assert: assertCreated},
		{name: "policy", options: []ValidatorConfigOption{WithValidatorAllowedTokenTypes("Bearer", "DPoP"), WithValidatorAllowedIssuedTokenTypes("urn:ietf:params:oauth:token-type:access_token"), WithValidatorRequireAccessToken(false), WithValidatorAllowIDToken(true), WithValidatorRequireIDToken(true), WithValidatorRequireIssuedTokenType(true), WithValidatorRuntimeOptions()}, assert: assertCreated},
		{name: "nil option", options: []ValidatorConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil access validator", options: []ValidatorConfigOption{WithValidatorAccessTokenValidator(nil)}, assert: assertMisconfigured},
		{name: "nil refresh validator", options: []ValidatorConfigOption{WithValidatorRefreshTokenValidator(nil)}, assert: assertMisconfigured},
		{name: "nil ID validator", options: []ValidatorConfigOption{WithValidatorIDTokenValidator(nil)}, assert: assertMisconfigured},
		{name: "no token types", options: []ValidatorConfigOption{WithValidatorAllowedTokenTypes()}, assert: assertMisconfigured},
		{name: "empty token type", options: []ValidatorConfigOption{WithValidatorAllowedTokenTypes("")}, assert: assertMisconfigured},
		{name: "no issued token types", options: []ValidatorConfigOption{WithValidatorAllowedIssuedTokenTypes()}, assert: assertMisconfigured},
		{name: "invalid issued token type", options: []ValidatorConfigOption{WithValidatorAllowedIssuedTokenTypes("access_token")}, assert: assertMisconfigured},
		{name: "contradictory ID token policy", options: []ValidatorConfigOption{WithValidatorAllowIDToken(false), WithValidatorRequireIDToken(true)}, assert: assertMisconfigured},
		{name: "invalid dependency options", options: []ValidatorConfigOption{WithValidatorAccessTokenValidatorOptions(nil)}, assert: assertMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewValidator(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	valid := &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer", ExpiresIn: time.Minute, Scope: "openid profile"}
	cause := errors.New("token validation failure")
	failingValidator, err := NewValidator(WithValidatorAccessTokenValidator(&tokenValidatorStub{err: cause}))
	if err != nil {
		t.Fatalf("NewValidator() failed: %v", err)
	}

	assertValid := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Validate() failed: %v", err)
		}
	}
	assertCategory := func(category error) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, category) {
				t.Fatalf("Validate() error = %v, want %v", err, category)
			}
		}
	}
	assertCause := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, cause) {
			t.Fatalf("Validate() error = %v, want preserved cause %v", err, cause)
		}
	}

	tests := []struct {
		name      string
		validator *Validator
		artifact  *TokenResponse
		assert    func(*testing.T, error)
	}{
		{name: "valid", validator: mustValidator(t), artifact: valid, assert: assertValid},
		{name: "case-insensitive token type", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "bEaReR"}, assert: assertValid},
		{name: "nil validator", artifact: valid, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "invalid validator", validator: &Validator{}, artifact: valid, assert: assertCategory(vapi.ErrMisconfigured)},
		{name: "nil response", validator: mustValidator(t), assert: assertCategory(vapi.ErrMalformed)},
		{name: "missing access token", validator: mustValidator(t), artifact: &TokenResponse{TokenType: "Bearer"}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "explicitly allowed ID-only response", validator: mustValidator(t, WithValidatorRequireAccessToken(false), WithValidatorRequireIDToken(true)), artifact: &TokenResponse{IdToken: &jwt.Token{}}, assert: assertValid},
		{name: "missing token type", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "disallowed token type", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "DPoP"}, assert: assertCategory(vapi.ErrPolicyRejected)},
		{name: "negative expiry", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer", ExpiresIn: -time.Second}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "invalid scope separator", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer", Scope: "read  write"}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "invalid scope character", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer", Scope: "read\\write"}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "invalid issued token type", validator: mustValidator(t), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer", IssuedTokenType: "access_token"}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "issued token type without access token field", validator: mustValidator(t, WithValidatorRequireAccessToken(false)), artifact: &TokenResponse{IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token"}, assert: assertCategory(vapi.ErrMalformed)},
		{name: "missing required issued token type", validator: mustValidator(t, WithValidatorRequireIssuedTokenType(true)), artifact: valid, assert: assertCategory(vapi.ErrMalformed)},
		{name: "disallowed issued token type", validator: mustValidator(t, WithValidatorAllowedIssuedTokenTypes("urn:ietf:params:oauth:token-type:access_token")), artifact: &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer", IssuedTokenType: "urn:ietf:params:oauth:token-type:refresh_token"}, assert: assertCategory(vapi.ErrPolicyRejected)},
		{name: "ID token not allowed", validator: mustValidator(t, WithValidatorAllowIDToken(false)), artifact: &TokenResponse{AccessToken: &jwt.Token{}, IdToken: &jwt.Token{}, TokenType: "Bearer"}, assert: assertCategory(vapi.ErrPolicyRejected)},
		{name: "required ID token missing", validator: mustValidator(t, WithValidatorRequireIDToken(true)), artifact: valid, assert: assertCategory(vapi.ErrMalformed)},
		{name: "access token validation failure", validator: failingValidator, artifact: valid, assert: assertCause},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.validator.Validate(context.Background(), tt.artifact))
		})
	}
}

func TestValidator_ValidateOptions(t *testing.T) {
	order := []string{}
	decorate := func(name string) ValidatorOption {
		return func(next ValidateFunc) ValidateFunc {
			return func(ctx context.Context, artifact *TokenResponse) error {
				order = append(order, name+" before")
				err := next(ctx, artifact)
				order = append(order, name+" after")
				return err
			}
		}
	}
	validator := mustValidator(t, WithValidatorRuntimeOptions(decorate("configured")))
	artifact := &TokenResponse{AccessToken: &jwt.Token{}, TokenType: "Bearer"}
	if err := validator.Validate(context.Background(), artifact, decorate("per-call")); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	want := []string{"configured before", "per-call before", "per-call after", "configured after"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("Validate() option order = %v, want %v", order, want)
	}
	if err := validator.Validate(context.Background(), artifact, nil); !errors.Is(err, vapi.ErrMisconfigured) {
		t.Errorf("Validate() nil option error = %v, want %v", err, vapi.ErrMisconfigured)
	}
	if err := validator.Validate(context.Background(), artifact, func(ValidateFunc) ValidateFunc { return nil }); !errors.Is(err, vapi.ErrMisconfigured) {
		t.Errorf("Validate() nil decorator error = %v, want %v", err, vapi.ErrMisconfigured)
	}
}

func mustValidator(t *testing.T, options ...ValidatorConfigOption) *Validator {
	t.Helper()
	validator, err := NewValidator(options...)
	if err != nil {
		t.Fatalf("NewValidator() failed: %v", err)
	}
	return validator
}
