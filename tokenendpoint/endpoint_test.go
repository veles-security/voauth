package tokenendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/logger"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

type requestAuthenticatorStub struct {
	principal vapi.Principal
	err       error
}

type nonScopedPrincipal struct{ vapi.Principal }

func (a *requestAuthenticatorStub) Authenticate(context.Context, *http.Request) (vapi.Principal, error) {
	return a.principal, a.err
}

func TestNew(t *testing.T) {
	principal := sub.NewBasePrincipal("issuer", "subject", "user").WithGrantedScopes("read")
	authenticator := &requestAuthenticatorStub{principal: principal}
	callback := tokenendpoint.IssuerOptionsCallback(func(context.Context, vapi.ScopedPrincipal) (tokenendpoint.IssuerOptions, error) {
		return tokenendpoint.IssuerOptions{}, nil
	})
	grantResolverOption := tokenrequest.ResolverOption(func(_ tokenrequest.ResolveFunc) tokenrequest.ResolveFunc {
		return func(_ context.Context, _ *tokenrequest.TokenRequest, _ vapi.Principal) (vapi.Principal, error) {
			return principal, nil
		}
	})
	issuer, err := jwt.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() failed: %v", err)
	}
	writer, err := tokenresponse.NewWriter()
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	assertCreated := func(t *testing.T, endpoint *tokenendpoint.TokenEndpoint, err error) {
		if err != nil || endpoint == nil {
			t.Fatalf("New() = (%#v, %v), want endpoint", endpoint, err)
		}
	}
	assertMisconfigured := func(t *testing.T, endpoint *tokenendpoint.TokenEndpoint, err error) {
		if endpoint != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("New() = (%#v, %v), want (nil, %v)", endpoint, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []tokenendpoint.TokenEndpointConfigOption
		assert  func(*testing.T, *tokenendpoint.TokenEndpoint, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "direct bindings", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithTokenRequestAuthenticator(authenticator), tokenendpoint.WithIssuer(issuer), tokenendpoint.WithTokenResponseWriter(writer), tokenendpoint.WithIssuerOptionsCallback(callback)}, assert: assertCreated},
		{name: "configured bindings", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticatorOptions(tokenrequest.WithAuthenticatorResolverOptions(tokenrequest.WithResolverRuntimeOptions(grantResolverOption))),
			tokenendpoint.WithIssuerOptions(),
			tokenendpoint.WithTokenResponseWriterOptions(),
			tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedAccessToken, tokenendpoint.IssuedRefreshToken, tokenendpoint.IssuedIDToken),
			tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assert: assertCreated},
		{name: "nil endpoint option", options: []tokenendpoint.TokenEndpointConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil authenticator", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithTokenRequestAuthenticator(nil)}, assert: assertMisconfigured},
		{name: "invalid authenticator options", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithTokenRequestAuthenticatorOptions(nil)}, assert: assertMisconfigured},
		{name: "nil issuer", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithIssuer(nil)}, assert: assertMisconfigured},
		{name: "invalid issuer options", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithIssuerOptions(jwt.IssuerConfigOption(nil))}, assert: assertMisconfigured},
		{name: "nil writer", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithTokenResponseWriter(nil)}, assert: assertMisconfigured},
		{name: "no issued tokens", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithIssuedTokens()}, assert: assertMisconfigured},
		{name: "unsupported issued token", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedToken("unknown"))}, assert: assertMisconfigured},
		{name: "nil issuer callback", options: []tokenendpoint.TokenEndpointConfigOption{tokenendpoint.WithIssuerOptionsCallback(nil)}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tokenendpoint.New(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}

func TestTokenEndpoint_ServeHTTP(t *testing.T) {
	type errorRepresentation struct {
		Error string `json:"error"`
	}
	principal := sub.NewBasePrincipal("issuer", "user-1", "user").WithGrantedScopes("read", "write")
	validForm := url.Values{
		"grant_type":    {tokenrequest.ClientCredentialsGrantType},
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
		"scope":         {"read write"},
	}
	assertTokens := func(names ...string) func(*testing.T, *httptest.ResponseRecorder) {
		return func(t *testing.T, response *httptest.ResponseRecorder) {
			if response.Code != http.StatusOK {
				t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			for _, name := range names {
				if value, ok := got[name].(string); !ok || value == "" {
					t.Errorf("ServeHTTP() %s = %#v, want non-empty token", name, got[name])
				}
			}
			if got["scope"] != "read write" {
				t.Errorf("ServeHTTP() scope = %#v, want %q", got["scope"], "read write")
			}
		}
	}
	assertError := func(status int, code string) func(*testing.T, *httptest.ResponseRecorder) {
		return func(t *testing.T, response *httptest.ResponseRecorder) {
			if response.Code != status {
				t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, status, response.Body.String())
			}
			var got errorRepresentation
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if !reflect.DeepEqual(got, errorRepresentation{Error: code}) {
				t.Fatalf("ServeHTTP() response = %#v, want error %q", got, code)
			}
		}
	}
	callback := tokenendpoint.IssuerOptionsCallback(func(_ context.Context, gotPrincipal vapi.ScopedPrincipal) (tokenendpoint.IssuerOptions, error) {
		if gotPrincipal != principal {
			return tokenendpoint.IssuerOptions{}, vapi.ErrInternal
		}
		return tokenendpoint.IssuerOptions{
			AccessToken:  []jwt.IssuerOption{jwt.WithIssuer("issuer"), jwt.WithExp(5 * time.Minute), jwt.WithClaims(jwt.Cliams{"use": "access"})},
			RefreshToken: []jwt.IssuerOption{jwt.WithIssuer("issuer"), jwt.WithClaims(jwt.Cliams{"use": "refresh"})},
			IDToken:      []jwt.IssuerOption{jwt.WithIssuer("issuer"), jwt.WithClaims(jwt.Cliams{"use": "id"})},
		}, nil
	})
	tests := []struct {
		name       string
		method     string
		body       string
		options    []tokenendpoint.TokenEndpointConfigOption
		assertions func(*testing.T, *httptest.ResponseRecorder)
	}{
		{name: "issues configured tokens", method: http.MethodPost, body: validForm.Encode(), options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{principal: principal}),
			tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedAccessToken, tokenendpoint.IssuedRefreshToken, tokenendpoint.IssuedIDToken),
			tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assertions: assertTokens("access_token", "refresh_token", "id_token")},
		{name: "supports ID token only", method: http.MethodPost, body: validForm.Encode(), options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{principal: principal}),
			tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedIDToken),
			tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assertions: assertTokens("id_token")},
		{name: "rejects unsupported method", method: http.MethodGet, body: validForm.Encode(), options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{principal: principal}), tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assertions: func(t *testing.T, response *httptest.ResponseRecorder) {
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("ServeHTTP() = status %d Allow %q, want 405 Allow POST", response.Code, response.Header().Get("Allow"))
			}
		}},
		{name: "maps resolution failure", method: http.MethodPost, body: validForm.Encode(), options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{err: vapi.ErrUnauthenticated}), tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assertions: assertError(http.StatusUnauthorized, "invalid_client")},
		{name: "rejects non-scoped principal", method: http.MethodPost, body: validForm.Encode(), options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{principal: nonScopedPrincipal{Principal: sub.NewBasePrincipal("issuer", "user-1", "user")}}), tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assertions: assertError(http.StatusBadRequest, "invalid_grant")},
		{name: "maps issuer callback failure", method: http.MethodPost, body: validForm.Encode(), options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{principal: principal}),
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, vapi.ScopedPrincipal) (tokenendpoint.IssuerOptions, error) {
				return tokenendpoint.IssuerOptions{}, vapi.ErrPolicyRejected
			}),
		}, assertions: assertError(http.StatusBadRequest, "invalid_grant")},
		{name: "rejects malformed form", method: http.MethodPost, body: "%", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(callback),
		}, assertions: assertError(http.StatusBadRequest, "invalid_request")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := tokenendpoint.New(tt.options...)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			request := httptest.NewRequest(tt.method, "/token", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, request)
			tt.assertions(t, response)
		})
	}
}

func TestTokenEndpoint_ServeHTTP_LogsAuthenticationAndIssuedTokens(t *testing.T) {
	var output bytes.Buffer
	originalLogger := logger.GetLogger()
	logger.SetLogger(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { logger.SetLogger(originalLogger) })

	principal := sub.NewBasePrincipal("issuer", "user-1", "user").WithGrantedScopes("read")
	endpoint, err := tokenendpoint.New(
		tokenendpoint.WithTokenRequestAuthenticator(&requestAuthenticatorStub{principal: principal}),
		tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedAccessToken, tokenendpoint.IssuedRefreshToken),
		tokenendpoint.WithIssuerOptionsCallback(func(context.Context, vapi.ScopedPrincipal) (tokenendpoint.IssuerOptions, error) {
			return tokenendpoint.IssuerOptions{
				AccessToken:  []jwt.IssuerOption{jwt.WithIssuer("issuer")},
				RefreshToken: []jwt.IssuerOption{jwt.WithIssuer("issuer")},
			}, nil
		}),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type":    {tokenrequest.ClientCredentialsGrantType},
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}

	logs := output.String()
	for _, expected := range []string{
		`"msg":"token endpoint principal authenticated","subject_id":"user-1"`,
		`"msg":"token endpoint tokens issued","token_types":["access_token","refresh_token"]`,
	} {
		if !strings.Contains(logs, expected) {
			t.Errorf("logs = %q, want entry containing %q", logs, expected)
		}
	}
}
