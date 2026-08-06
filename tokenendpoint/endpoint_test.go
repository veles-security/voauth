package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

func TestNew(t *testing.T) {
	assertCreated := func(t *testing.T, endpoint *tokenendpoint.TokenEndpoint, err error) {
		t.Helper()
		if err != nil || endpoint == nil {
			t.Fatalf("New() = (%#v, %v), want non-nil endpoint and nil error", endpoint, err)
		}
	}
	assertMisconfigured := func(t *testing.T, endpoint *tokenendpoint.TokenEndpoint, err error) {
		t.Helper()
		if endpoint != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("New() = (%#v, %v), want nil endpoint and %v", endpoint, err, vapi.ErrMisconfigured)
		}
	}

	tests := []struct {
		name       string
		options    []tokenendpoint.TokenEndpointConfigOption
		assertions func(*testing.T, *tokenendpoint.TokenEndpoint, error)
	}{
		{name: "creates endpoint", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) { return nil, nil }),
		}, assertions: assertCreated},
		{name: "requires issuer callback", assertions: assertMisconfigured},
		{name: "accepts component options", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestValidatorOption(tokenrequest.WithAllowedGrantTypes(tokenrequest.ClientCredentialsGrantType)),
			tokenendpoint.WithClientCredentialsValidatorOption(clientcredentials.WithAllowedMethods(clientcredentials.ClientSecretPostAuthMethod)),
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) { return nil, nil }),
		}, assertions: assertCreated},
		{name: "rejects nil endpoint option", options: []tokenendpoint.TokenEndpointConfigOption{nil}, assertions: assertMisconfigured},
		{name: "categorizes component option failure", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenRequestValidatorOption(tokenrequest.WithAllowedScopes()),
		}, assertions: assertMisconfigured},
		{name: "categorizes client credentials validator option failure", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithClientCredentialsValidatorOption(clientcredentials.WithAllowedMethods()),
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) { return nil, nil }),
		}, assertions: assertMisconfigured},
		{name: "rejects nil issuer callback", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(nil),
		}, assertions: assertMisconfigured},
		{name: "rejects nil response callback", options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithTokenResponseCallback(nil),
		}, assertions: assertMisconfigured},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := tokenendpoint.New(test.options...)
			test.assertions(t, endpoint, err)
		})
	}
}

func TestTokenEndpoint_ServeHTTP(t *testing.T) {
	type errorRepresentation struct {
		Error string `json:"error"`
	}
	assertSuccess := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got["token_type"] != "Bearer" || got["scope"] != "read" || got["expires_in"] != float64(300) {
			t.Fatalf("ServeHTTP() response = %#v, want bearer token with read scope and 300 second lifetime", got)
		}
		if accessToken, ok := got["access_token"].(string); !ok || accessToken == "" {
			t.Fatalf("ServeHTTP() access_token = %#v, want non-empty string", got["access_token"])
		}
	}
	assertError := func(status int, code string) func(*testing.T, *httptest.ResponseRecorder) {
		return func(t *testing.T, response *httptest.ResponseRecorder) {
			t.Helper()
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

	validForm := url.Values{
		"grant_type":    {tokenrequest.ClientCredentialsGrantType},
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
		"scope":         {"read"},
	}
	tests := []struct {
		name       string
		method     string
		form       url.Values
		options    []tokenendpoint.TokenEndpointConfigOption
		assertions func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "issues token using callbacks",
			method: http.MethodPost,
			form:   validForm,
			options: []tokenendpoint.TokenEndpointConfigOption{
				tokenendpoint.WithTokenRequestValidatorOption(
					tokenrequest.WithAllowedGrantTypes(tokenrequest.ClientCredentialsGrantType),
					tokenrequest.WithAllowedScopes("read"),
				),
				tokenendpoint.WithIssuerOptionsCallback(func(_ context.Context, request *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) {
					if request.ClientCredentials.ClientId != "client-1" || request.ClientCredentials.ClientSecret != "secret" {
						return nil, vapi.ErrUnauthenticated
					}
					return []jwt.IssuerOption{jwt.WithIssuer("https://issuer.example"), jwt.WithSubject("client-1"), jwt.WithExp(5 * time.Minute)}, nil
				}),
				tokenendpoint.WithTokenResponseCallback(func(_ context.Context, request *tokenrequest.TokenRequest, accessToken *jwt.Token) (*tokenresponse.TokenResponse, error) {
					return &tokenresponse.TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: 5 * time.Minute, Scope: request.Scope}, nil
				}),
			},
			assertions: assertSuccess,
		},
		{name: "rejects unsupported method", method: http.MethodGet, form: validForm, options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) { return nil, nil }),
		}, assertions: func(t *testing.T, response *httptest.ResponseRecorder) {
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("ServeHTTP() = status %d Allow %q, want 405 Allow POST", response.Code, response.Header().Get("Allow"))
			}
		}},
		{name: "rejects malformed request", method: http.MethodPost, form: url.Values{"grant_type": {tokenrequest.ClientCredentialsGrantType}}, options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) { return nil, nil }),
		}, assertions: assertError(http.StatusBadRequest, "invalid_request")},
		{name: "maps authentication callback failure", method: http.MethodPost, form: validForm, options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) {
				return nil, vapi.ErrUnauthenticated
			}),
		}, assertions: assertError(http.StatusUnauthorized, "invalid_client")},
		{name: "rejects nil callback response", method: http.MethodPost, form: validForm, options: []tokenendpoint.TokenEndpointConfigOption{
			tokenendpoint.WithIssuerOptionsCallback(func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) { return nil, nil }),
			tokenendpoint.WithTokenResponseCallback(func(context.Context, *tokenrequest.TokenRequest, *jwt.Token) (*tokenresponse.TokenResponse, error) {
				return nil, nil
			}),
		}, assertions: assertError(http.StatusInternalServerError, "server_error")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := tokenendpoint.New(test.options...)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			request := httptest.NewRequest(test.method, "/token", strings.NewReader(test.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, request)
			test.assertions(t, response)
		})
	}
}
