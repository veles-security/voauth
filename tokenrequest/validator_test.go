package tokenrequest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/token"
	"github.com/veles-security/voauth/tokenrequest"
)

type anyTokenStub struct{}

func (anyTokenStub) Kind() string      { return "test:token" }
func (anyTokenStub) TokenType() string { return "test" }

type anyTokenValidatorStub struct {
	got token.AnyToken
	err error
}

func (s *anyTokenValidatorStub) ValidateAnyToken(_ context.Context, artifact token.AnyToken) error {
	s.got = artifact
	return s.err
}

func TestValidator_Validate(t *testing.T) {
	refreshToken := anyTokenStub{}
	assertion := anyTokenStub{}
	failure := vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("rejected token"))

	assertValid := func(t *testing.T, err error) {
		if err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	}
	assertRejected := func(t *testing.T, err error) {
		if !errors.Is(err, vapi.ErrPolicyRejected) {
			t.Fatalf("Validate() error = %v, want %v", err, vapi.ErrPolicyRejected)
		}
	}

	tests := []struct {
		name      string
		artifact  *tokenrequest.TokenRequest
		validator *anyTokenValidatorStub
		options   []tokenrequest.ValidatorConfigOption
		assert    func(*testing.T, error)
		wantToken token.AnyToken
	}{
		{
			name: "validates refresh token",
			artifact: &tokenrequest.TokenRequest{
				GrantType:         tokenrequest.RefreshTokenGrantType,
				ClientCredentials: clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client", ClientSecret: "secret"},
				RefreshToken:      refreshToken,
			},
			validator: &anyTokenValidatorStub{},
			assert:    assertValid,
			wantToken: refreshToken,
		},
		{
			name: "propagates refresh token validation failure",
			artifact: &tokenrequest.TokenRequest{
				GrantType:         tokenrequest.RefreshTokenGrantType,
				ClientCredentials: clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client", ClientSecret: "secret"},
				RefreshToken:      refreshToken,
			},
			validator: &anyTokenValidatorStub{err: failure},
			assert:    assertRejected,
			wantToken: refreshToken,
		},
		{
			name: "validates bearer assertion",
			artifact: &tokenrequest.TokenRequest{
				GrantType:         tokenrequest.JwtBearerGrantType,
				ClientCredentials: clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client", ClientSecret: "secret"},
				Assertion:         assertion,
			},
			validator: &anyTokenValidatorStub{},
			assert:    assertValid,
			wantToken: assertion,
		},
		{
			name: "propagates bearer assertion validation failure",
			artifact: &tokenrequest.TokenRequest{
				GrantType:         tokenrequest.Saml2BearerGrantType,
				ClientCredentials: clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client", ClientSecret: "secret"},
				Assertion:         assertion,
			},
			validator: &anyTokenValidatorStub{err: failure},
			assert:    assertRejected,
			wantToken: assertion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.artifact.GrantType == tokenrequest.RefreshTokenGrantType {
				tt.options = []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorRefreshTokenValidator(tt.validator)}
			} else {
				tt.options = []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorAssertionTokenValidator(tt.validator)}
			}
			validator, err := tokenrequest.NewValidator(tt.options...)
			if err != nil {
				t.Fatal(err)
			}
			gotErr := validator.Validate(context.Background(), tt.artifact)
			tt.assert(t, gotErr)
			if tt.validator.got != tt.wantToken {
				t.Errorf("validated token = %#v, want %#v", tt.validator.got, tt.wantToken)
			}
		})
	}
}

func TestNewValidator(t *testing.T) {
	assertCreated := func(t *testing.T, validator *tokenrequest.Validator, err error) {
		if err != nil || validator == nil {
			t.Fatalf("NewValidator() = (%#v, %v), want validator", validator, err)
		}
	}
	assertMisconfigured := func(t *testing.T, validator *tokenrequest.Validator, err error) {
		if validator != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewValidator() = (%#v, %v), want (nil, %v)", validator, err, vapi.ErrMisconfigured)
		}
	}

	tests := []struct {
		name    string
		options []tokenrequest.ValidatorConfigOption
		assert  func(*testing.T, *tokenrequest.Validator, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "refresh token validator options", options: []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorRefreshTokenValidatorOptions()}, assert: assertCreated},
		{name: "assertion token validator options", options: []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorAssertionTokenValidatorOptions()}, assert: assertCreated},
		{name: "nil refresh token validator", options: []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorRefreshTokenValidator(nil)}, assert: assertMisconfigured},
		{name: "nil assertion token validator", options: []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorAssertionTokenValidator(nil)}, assert: assertMisconfigured},
		{name: "invalid refresh token validator options", options: []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorRefreshTokenValidatorOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid assertion token validator options", options: []tokenrequest.ValidatorConfigOption{tokenrequest.WithValidatorAssertionTokenValidatorOptions(nil)}, assert: assertMisconfigured},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tokenrequest.NewValidator(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}
