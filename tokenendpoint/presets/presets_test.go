package presets_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenendpoint/presets"
	"github.com/veles-security/voauth/tokenrequest"
)

func TestAuthenticator(t *testing.T) {
	client := sub.NewBasePrincipal("issuer", "client-1", "client")
	subject := sub.NewBasePrincipal("issuer", "subject-1", "subject")
	endpoint, err := tokenendpoint.New(presets.Authenticator(
		presets.GrantTypes(tokenrequest.ClientCredentialsGrantType),
		presets.ClientAuthentication(clientcredentials.ClientSecretPostAuthMethod, func(_ context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
			if credentials.ClientId != "client-1" || credentials.ClientSecret != "secret" {
				return nil, vapi.ErrUnauthenticated
			}
			return client, nil
		}),
		presets.ResolveSubject(func(_ context.Context, _ *tokenrequest.TokenRequest, gotClient vapi.Principal) (vapi.Principal, error) {
			if gotClient != client {
				return nil, vapi.ErrInternal
			}
			return subject, nil
		}),
	))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	form := url.Values{
		"grant_type":    {tokenrequest.ClientCredentialsGrantType},
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
	}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestAuthenticatorOptions(t *testing.T) {
	tests := []struct {
		name   string
		option presets.AuthenticatorOption
	}{
		{name: "nil option", option: nil},
		{name: "nil client callback", option: presets.ClientAuthentication(clientcredentials.ClientSecretPostAuthMethod, nil)},
		{name: "nil subject callback", option: presets.ResolveSubject(nil)},
		{name: "unsupported grant", option: presets.GrantTypes("unsupported")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tokenendpoint.New(presets.Authenticator(tt.option))
			if !errors.Is(err, vapi.ErrMisconfigured) {
				t.Fatalf("New() error = %v, want ErrMisconfigured", err)
			}
		})
	}
}

func TestTokens(t *testing.T) {
	principal := sub.NewBasePrincipal("issuer", "subject-1", "subject")
	called := make(map[string]bool)
	callback := func(name string) presets.TokenCallback {
		return func(_ context.Context, got vapi.ScopedPrincipal) ([]jwt.IssuerOption, error) {
			if got != principal {
				return nil, vapi.ErrInternal
			}
			called[name] = true
			return []jwt.IssuerOption{jwt.WithIssuer("issuer")}, nil
		}
	}

	endpoint, err := tokenendpoint.New(
		tokenendpoint.WithTokenRequestAuthenticator(&authenticatorStub{principal: principal}),
		presets.Tokens(
			presets.AccessToken(callback("access")),
			presets.RefreshToken(callback("refresh")),
			presets.IDToken(callback("id")),
		),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(""))
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	for _, name := range []string{"access", "refresh", "id"} {
		if !called[name] {
			t.Errorf("%s token callback was not called", name)
		}
	}
}

func TestTokenOptions(t *testing.T) {
	tests := []struct {
		name   string
		option presets.TokenOption
	}{
		{name: "nil option", option: nil},
		{name: "nil access callback", option: presets.AccessToken(nil)},
		{name: "nil refresh callback", option: presets.RefreshToken(nil)},
		{name: "nil ID callback", option: presets.IDToken(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tokenendpoint.New(presets.Tokens(tt.option))
			if !errors.Is(err, vapi.ErrMisconfigured) {
				t.Fatalf("New() error = %v, want ErrMisconfigured", err)
			}
		})
	}
}

func TestSigner(t *testing.T) {
	_, err := tokenendpoint.New(presets.Signer(nil))
	if !errors.Is(err, vapi.ErrMisconfigured) {
		t.Fatalf("New() error = %v, want ErrMisconfigured", err)
	}
}

type authenticatorStub struct {
	principal vapi.Principal
}

func (s *authenticatorStub) Authenticate(context.Context, *http.Request) (vapi.Principal, error) {
	return s.principal, nil
}
