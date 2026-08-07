package jwt

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/veles-security/vapi"
)

func TestNewValidator(t *testing.T) {
	cause := errors.New("config failure")

	assertCreated := func(t *testing.T, got *Validator, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("NewValidator() failed: %v", err)
		}
		if got == nil {
			t.Fatal("NewValidator() returned nil validator")
		}
	}
	assertMisconfigured := func(t *testing.T, got *Validator, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewValidator() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	assertCause := func(t *testing.T, got *Validator, err error) {
		t.Helper()
		assertMisconfigured(t, got, err)
		if !errors.Is(err, cause) {
			t.Errorf("NewValidator() error = %v, want preserved cause %v", err, cause)
		}
	}

	tests := []struct {
		name    string
		options []ValidatorConfigOption
		assert  func(*testing.T, *Validator, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "runtime options", options: []ValidatorConfigOption{WithValidatorRuntimeOptions(WithType("JWT"))}, assert: assertCreated},
		{name: "nil option", options: []ValidatorConfigOption{nil}, assert: assertMisconfigured},
		{name: "option failure", options: []ValidatorConfigOption{func(*Validator) error { return cause }}, assert: assertCause},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewValidator(tt.options...)
			tt.assert(t, got, err)
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	ctx := context.Background()
	token := &Token{Header: map[string]string{"typ": "JWT"}, Claims: map[string]any{}}
	cause := errors.New("policy failure")

	record := func(name string, order *[]string) ValidatorOption {
		return func(next ValidateFunc) ValidateFunc {
			return func(ctx context.Context, artifact *Token) error {
				*order = append(*order, name)
				return next(ctx, artifact)
			}
		}
	}
	fail := func(next ValidateFunc) ValidateFunc {
		return func(context.Context, *Token) error { return vapi.NewErrorCategory(vapi.ErrPolicyRejected, cause) }
	}
	nilDecorator := func(ValidateFunc) ValidateFunc { return nil }

	configuredOrder := []string{}
	configured, err := NewValidator(WithValidatorRuntimeOptions(record("configured", &configuredOrder)))
	if err != nil {
		t.Fatalf("NewValidator() failed: %v", err)
	}
	valid, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() failed: %v", err)
	}

	assertValid := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Validate() failed: %v", err)
		}
	}
	assertMalformed := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, vapi.ErrMalformed) {
			t.Fatalf("Validate() error = %v, want %v", err, vapi.ErrMalformed)
		}
	}
	assertMisconfigured := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("Validate() error = %v, want %v", err, vapi.ErrMisconfigured)
		}
	}
	assertRejected := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, vapi.ErrPolicyRejected) || !errors.Is(err, cause) {
			t.Fatalf("Validate() error = %v, want category %v and cause %v", err, vapi.ErrPolicyRejected, cause)
		}
	}

	tests := []struct {
		name      string
		validator *Validator
		artifact  *Token
		options   []ValidatorOption
		assert    func(*testing.T, error)
		wantOrder []string
	}{
		{name: "valid", validator: valid, artifact: token, assert: assertValid},
		{name: "configured before per call", validator: configured, artifact: token, options: []ValidatorOption{record("per-call", &configuredOrder)}, assert: assertValid, wantOrder: []string{"configured", "per-call"}},
		{name: "nil validator", artifact: token, assert: assertMisconfigured},
		{name: "nil artifact", validator: valid, assert: assertMalformed},
		{name: "policy rejection", validator: valid, artifact: token, options: []ValidatorOption{fail}, assert: assertRejected},
		{name: "nil option", validator: valid, artifact: token, options: []ValidatorOption{nil}, assert: assertMisconfigured},
		{name: "nil decorated function", validator: valid, artifact: token, options: []ValidatorOption{nilDecorator}, assert: assertMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantOrder != nil {
				configuredOrder = nil
			}
			err := tt.validator.Validate(ctx, tt.artifact, tt.options...)
			tt.assert(t, err)
			if tt.wantOrder != nil && !reflect.DeepEqual(configuredOrder, tt.wantOrder) {
				t.Errorf("Validate() option order = %v, want %v", configuredOrder, tt.wantOrder)
			}
		})
	}
}

func TestValidatorOptions(t *testing.T) {
	now := time.Now()

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

	tests := []struct {
		name     string
		artifact *Token
		option   ValidatorOption
		assert   func(*testing.T, error)
	}{
		{name: "type", artifact: &Token{Header: map[string]string{"typ": "JWT"}}, option: WithType("JWT"), assert: assertValid},
		{name: "wrong type", artifact: &Token{Header: map[string]string{"typ": "at+jwt"}}, option: WithType("JWT"), assert: assertCategory(vapi.ErrPolicyRejected)},
		{name: "nonce", artifact: &Token{Claims: map[string]any{"nonce": "expected"}}, option: WithNonce("expected"), assert: assertValid},
		{name: "wrong nonce", artifact: &Token{Claims: map[string]any{"nonce": "wrong"}}, option: WithNonce("expected"), assert: assertCategory(vapi.ErrBinding)},
		{name: "issuer", artifact: &Token{Claims: map[string]any{"iss": "issuer"}}, option: WithValidIssuer("issuer"), assert: assertValid},
		{name: "wrong issuer", artifact: &Token{Claims: map[string]any{"iss": "other"}}, option: WithValidIssuer("issuer"), assert: assertCategory(vapi.ErrWrongIssuer)},
		{name: "audience string", artifact: &Token{Claims: map[string]any{"aud": "api"}}, option: WithValidAudience("api"), assert: assertValid},
		{name: "audience array", artifact: &Token{Claims: map[string]any{"aud": []any{"other", "api"}}}, option: WithValidAudience("api"), assert: assertValid},
		{name: "wrong audience", artifact: &Token{Claims: map[string]any{"aud": "other"}}, option: WithValidAudience("api"), assert: assertCategory(vapi.ErrWrongAudience)},
		{name: "valid clock", artifact: &Token{Claims: map[string]any{"exp": float64(now.Add(time.Minute).Unix()), "nbf": float64(now.Add(-time.Minute).Unix())}}, option: WithValidClock(0), assert: assertValid},
		{name: "expired", artifact: &Token{Claims: map[string]any{"exp": float64(now.Add(-time.Minute).Unix())}}, option: WithValidClock(0), assert: assertCategory(vapi.ErrExpired)},
		{name: "not yet valid", artifact: &Token{Claims: map[string]any{"nbf": float64(now.Add(time.Minute).Unix())}}, option: WithValidClock(0), assert: assertCategory(vapi.ErrNotYetValid)},
		{name: "malformed clock", artifact: &Token{Claims: map[string]any{"exp": "tomorrow"}}, option: WithValidClock(0), assert: assertCategory(vapi.ErrMalformed)},
	}

	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() failed: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, validator.Validate(context.Background(), tt.artifact, tt.option))
		})
	}
}
