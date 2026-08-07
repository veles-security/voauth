package clientcredentials_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
)

type credentialsValidatorStub struct {
	err       error
	validated **clientcredentials.ClientCredentials
}

func (v *credentialsValidatorStub) Validate(_ context.Context, credentials *clientcredentials.ClientCredentials, _ ...clientcredentials.ValidatorOption) error {
	if v.validated != nil {
		*v.validated = credentials
	}
	return v.err
}

func TestAuthenticator_Authenticate(t *testing.T) {
	wantCredentials := &clientcredentials.ClientCredentials{
		AuthMethod:   clientcredentials.ClientSecretPostAuthMethod,
		ClientId:     "client-1",
		ClientSecret: "secret",
	}
	wantPrincipal := sub.NewBasePrincipal("clients", "client-1", "service")
	callbackFailure := errors.New("invalid client secret")
	validationFailure := errors.New("invalid credentials shape")

	assertAuthenticated := func(t *testing.T, got vapi.Principal, err error) {
		if err != nil {
			t.Fatalf("Authenticate() failed: %v", err)
		}
		if !reflect.DeepEqual(got, wantPrincipal) {
			t.Errorf("Authenticate() principal = %#v, want %#v", got, wantPrincipal)
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

	var validated *clientcredentials.ClientCredentials
	validCallback := clientcredentials.AuthCallback(func(_ context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		if !reflect.DeepEqual(credentials, wantCredentials) {
			t.Errorf("callback credentials = %#v, want %#v", credentials, wantCredentials)
		}
		return wantPrincipal, nil
	})
	valid, err := clientcredentials.NewAuthenticator(
		clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretPostAuthMethod, validCallback),
		clientcredentials.WithAuthenticatorValidator(&credentialsValidatorStub{validated: &validated}),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	failing, err := clientcredentials.NewAuthenticator(clientcredentials.WithAuthenticatorAuthCallback(
		clientcredentials.ClientSecretPostAuthMethod,
		func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
			return nil, callbackFailure
		},
	))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	nilPrincipal, err := clientcredentials.NewAuthenticator(clientcredentials.WithAuthenticatorAuthCallback(
		clientcredentials.ClientSecretPostAuthMethod,
		func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) { return nil, nil },
	))
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}
	invalid, err := clientcredentials.NewAuthenticator(
		clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretPostAuthMethod, validCallback),
		clientcredentials.WithAuthenticatorValidator(&credentialsValidatorStub{err: validationFailure}),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() failed: %v", err)
	}

	tests := []struct {
		name          string
		authenticator *clientcredentials.Authenticator
		credentials   *clientcredentials.ClientCredentials
		assert        func(*testing.T, vapi.Principal, error)
	}{
		{name: "authenticated after validation", authenticator: valid, credentials: wantCredentials, assert: assertAuthenticated},
		{name: "without configured callback for method", authenticator: valid, credentials: &clientcredentials.ClientCredentials{AuthMethod: clientcredentials.PrivateKeyJwtAuthMethod}, assert: assertUnauthenticated(nil)},
		{name: "callback failure", authenticator: failing, credentials: wantCredentials, assert: assertUnauthenticated(callbackFailure)},
		{name: "callback returns nil principal", authenticator: nilPrincipal, credentials: wantCredentials, assert: assertUnauthenticated(nil)},
		{name: "validation failure", authenticator: invalid, credentials: wantCredentials, assert: assertUnauthenticated(validationFailure)},
		{name: "nil credentials", authenticator: valid, assert: assertMalformed},
		{name: "nil receiver", credentials: wantCredentials, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated = nil
			got, gotErr := tt.authenticator.Authenticate(context.Background(), tt.credentials)
			tt.assert(t, got, gotErr)
			if tt.name == "authenticated after validation" && validated != wantCredentials {
				t.Errorf("validator credentials = %#v, want %#v", validated, wantCredentials)
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	callback := clientcredentials.AuthCallback(func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		return sub.NewBasePrincipal("clients", "client-1", "service"), nil
	})
	assertCreated := func(t *testing.T, got *clientcredentials.Authenticator, err error) {
		if err != nil || got == nil {
			t.Fatalf("NewAuthenticator() = (%#v, %v), want authenticator", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *clientcredentials.Authenticator, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewAuthenticator() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []clientcredentials.AuthenticatorConfigOption
		assert  func(*testing.T, *clientcredentials.Authenticator, error)
	}{
		{name: "callback", options: []clientcredentials.AuthenticatorConfigOption{clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretBasicAuthMethod, callback)}, assert: assertCreated},
		{name: "validator options", options: []clientcredentials.AuthenticatorConfigOption{clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretBasicAuthMethod, callback), clientcredentials.WithAuthenticatorValidatorOptions()}, assert: assertCreated},
		{name: "missing callback", assert: assertMisconfigured},
		{name: "nil config option", options: []clientcredentials.AuthenticatorConfigOption{nil}, assert: assertMisconfigured},
		{name: "empty callback method", options: []clientcredentials.AuthenticatorConfigOption{clientcredentials.WithAuthenticatorAuthCallback("", callback)}, assert: assertMisconfigured},
		{name: "nil callback", options: []clientcredentials.AuthenticatorConfigOption{clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretBasicAuthMethod, nil)}, assert: assertMisconfigured},
		{name: "nil validator", options: []clientcredentials.AuthenticatorConfigOption{clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretBasicAuthMethod, callback), clientcredentials.WithAuthenticatorValidator(nil)}, assert: assertMisconfigured},
		{name: "invalid validator options", options: []clientcredentials.AuthenticatorConfigOption{clientcredentials.WithAuthenticatorAuthCallback(clientcredentials.ClientSecretBasicAuthMethod, callback), clientcredentials.WithAuthenticatorValidatorOptions(clientcredentials.ValidatorConfigOption(nil))}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := clientcredentials.NewAuthenticator(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}
