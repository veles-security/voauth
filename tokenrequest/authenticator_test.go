package tokenrequest_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/tokenrequest"
)

type tokenRequestValidatorStub struct {
	err   error
	order *[]string
}

func (v *tokenRequestValidatorStub) Validate(context.Context, *tokenrequest.TokenRequest, ...tokenrequest.ValidatorOption) error {
	if v.order != nil {
		*v.order = append(*v.order, "validate")
	}
	return v.err
}

type clientAuthenticatorStub struct {
	principal vapi.Principal
	err       error
	order     *[]string
}

func (a *clientAuthenticatorStub) Authenticate(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
	if a.order != nil {
		*a.order = append(*a.order, "client")
	}
	return a.principal, a.err
}

func TestAuthenticator_Authenticate(t *testing.T) {
	request := &tokenrequest.TokenRequest{
		GrantType: tokenrequest.PasswordGrantType,
		ClientCredentials: clientcredentials.ClientCredentials{
			AuthMethod: clientcredentials.ClientSecretPostAuthMethod,
			ClientId:   "client-1",
		},
		Username: "user-1",
		Password: "secret",
		Scope:    "read write",
	}
	clientPrincipal := sub.NewBasePrincipal("clients", "client-1", "service")
	wantPrincipal := sub.NewBasePrincipal("issuer", "user-1", "user").WithGrantedScopes("read", "write")
	validationFailure := errors.New("invalid token request")
	clientFailure := errors.New("invalid client")
	callbackFailure := errors.New("invalid resource owner")

	assertAuthenticated := func(t *testing.T, got vapi.Principal, err error) {
		if err != nil {
			t.Fatalf("Authenticate() failed: %v", err)
		}
		if !reflect.DeepEqual(got, wantPrincipal) {
			t.Errorf("Authenticate() principal = %#v, want %#v", got, wantPrincipal)
		}
		if _, ok := got.(vapi.ScopedPrincipal); !ok {
			t.Errorf("Authenticate() principal type = %T, want vapi.ScopedPrincipal", got)
		}
	}
	assertClient := func(t *testing.T, got vapi.Principal, err error) {
		if err != nil || got != clientPrincipal {
			t.Fatalf("Authenticate() = (%#v, %v), want client principal", got, err)
		}
	}
	assertMalformed := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMalformed) {
			t.Fatalf("Authenticate() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMalformed)
		}
	}
	assertMisconfigured := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("Authenticate() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	assertUnauthenticated := func(cause error) func(*testing.T, vapi.Principal, error) {
		return func(t *testing.T, got vapi.Principal, err error) {
			if got != nil || !errors.Is(err, vapi.ErrUnauthenticated) {
				t.Fatalf("Authenticate() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrUnauthenticated)
			}
			if cause != nil && !errors.Is(err, cause) {
				t.Errorf("Authenticate() error = %v, want preserved cause %v", err, cause)
			}
		}
	}

	order := []string{}
	callback := tokenrequest.AuthCallback(func(_ context.Context, gotRequest *tokenrequest.TokenRequest, gotClient vapi.Principal) (vapi.Principal, error) {
		order = append(order, "grant")
		if gotRequest != request {
			t.Errorf("callback request = %#v, want %#v", gotRequest, request)
		}
		if gotClient != clientPrincipal {
			t.Errorf("callback client = %#v, want %#v", gotClient, clientPrincipal)
		}
		return wantPrincipal, nil
	})
	valid, err := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{order: &order}),
		tokenrequest.WithAuthenticatorClientAuthenticator(&clientAuthenticatorStub{principal: clientPrincipal, order: &order}),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	clientOnly, err := tokenrequest.NewAuthenticator(tokenrequest.WithAuthenticatorClientAuthenticator(&clientAuthenticatorStub{principal: clientPrincipal}))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	validationFails, _ := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{err: validationFailure}),
	)
	clientFails, _ := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback),
		tokenrequest.WithAuthenticatorClientAuthenticator(&clientAuthenticatorStub{err: clientFailure}),
	)
	callbackFails, _ := tokenrequest.NewAuthenticator(tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType,
		func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
			return nil, callbackFailure
		}))
	callbackReturnsNil, _ := tokenrequest.NewAuthenticator(tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType,
		func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
			return nil, nil
		}))

	tests := []struct {
		name          string
		authenticator *tokenrequest.Authenticator
		request       *tokenrequest.TokenRequest
		assert        func(*testing.T, vapi.Principal, error)
	}{
		{name: "grant subject after client authentication", authenticator: valid, request: request, assert: assertAuthenticated},
		{name: "client credentials subject is client", authenticator: clientOnly, request: &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType}, assert: assertClient},
		{name: "missing grant callback", authenticator: clientOnly, request: request, assert: assertUnauthenticated(nil)},
		{name: "validation failure", authenticator: validationFails, request: request, assert: assertUnauthenticated(validationFailure)},
		{name: "client authentication failure", authenticator: clientFails, request: request, assert: assertUnauthenticated(clientFailure)},
		{name: "grant callback failure", authenticator: callbackFails, request: request, assert: assertUnauthenticated(callbackFailure)},
		{name: "grant callback returns nil", authenticator: callbackReturnsNil, request: request, assert: assertUnauthenticated(nil)},
		{name: "nil request", authenticator: valid, assert: assertMalformed},
		{name: "nil receiver", request: request, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = order[:0]
			got, gotErr := tt.authenticator.Authenticate(context.Background(), tt.request)
			tt.assert(t, got, gotErr)
			if tt.name == "grant subject after client authentication" {
				wantOrder := []string{"validate", "client", "grant"}
				if !reflect.DeepEqual(order, wantOrder) {
					t.Errorf("authentication order = %#v, want %#v", order, wantOrder)
				}
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	callback := tokenrequest.AuthCallback(func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
		return sub.NewBasePrincipal("issuer", "subject", "user"), nil
	})
	clientCallback := clientcredentials.AuthCallback(func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		return sub.NewBasePrincipal("clients", "client-1", "service"), nil
	})
	assertCreated := func(t *testing.T, got *tokenrequest.Authenticator, err error) {
		if err != nil || got == nil {
			t.Fatalf("NewAuthenticator() = (%#v, %v), want authenticator", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *tokenrequest.Authenticator, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewAuthenticator() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []tokenrequest.AuthenticatorConfigOption
		assert  func(*testing.T, *tokenrequest.Authenticator, error)
	}{
		{name: "grant callback", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback)}, assert: assertCreated},
		{name: "direct client authenticator", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorClientAuthenticator(&clientAuthenticatorStub{principal: sub.NewBasePrincipal("clients", "client-1", "service")})}, assert: assertCreated},
		{name: "client authenticator options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorClientAuthenticatorOptions(clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretPostAuthMethod, clientCallback))}, assert: assertCreated},
		{name: "validator options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback), tokenrequest.WithAuthenticatorValidatorOptions()}, assert: assertCreated},
		{name: "missing authentication", assert: assertMisconfigured},
		{name: "nil config option", options: []tokenrequest.AuthenticatorConfigOption{nil}, assert: assertMisconfigured},
		{name: "empty grant type", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorAuthCallback("", callback)}, assert: assertMisconfigured},
		{name: "nil callback", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, nil)}, assert: assertMisconfigured},
		{name: "nil validator", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback), tokenrequest.WithAuthenticatorValidator(nil)}, assert: assertMisconfigured},
		{name: "invalid validator options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.PasswordGrantType, callback), tokenrequest.WithAuthenticatorValidatorOptions(tokenrequest.ValidatorConfigOption(nil))}, assert: assertMisconfigured},
		{name: "nil client authenticator", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorClientAuthenticator(nil)}, assert: assertMisconfigured},
		{name: "invalid client authenticator options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorClientAuthenticatorOptions()}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tokenrequest.NewAuthenticator(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}
