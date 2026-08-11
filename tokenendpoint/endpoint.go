package tokenendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

type IssuedToken string

const (
	IssuedAccessToken  IssuedToken = "access_token"
	IssuedRefreshToken IssuedToken = "refresh_token"
	IssuedIDToken      IssuedToken = "id_token"
)

// IssuerOptions contains the token-specific options prepared by application
// policy for the configured tokens.
type IssuerOptions struct {
	AccessToken  []jwt.IssuerOption
	RefreshToken []jwt.IssuerOption
	IDToken      []jwt.IssuerOption
}

// IssuerOptionsCallback derives token-specific issue options from the token
// subject.
type IssuerOptionsCallback func(context.Context, vapi.ScopedPrincipal) (IssuerOptions, error)

type TokenEndpointConfigOption func(*TokenEndpoint) error

// TokenEndpoint implements an OAuth 2.0 token endpoint HTTP handler.
type TokenEndpoint struct {
	requestAuthenticator  vapi.Authenticator[*http.Request]
	issuer                vapi.Issuer[jwt.IssuerOption, *jwt.Token]
	issuerOptionsCallback IssuerOptionsCallback
	responseWriter        vapi.Writer[http.ResponseWriter, *tokenresponse.TokenResponse, tokenresponse.WriterOption]
	issuedTokens          map[IssuedToken]struct{}
}

// New constructs a token endpoint and its configured components.
func New(configOptions ...TokenEndpointConfigOption) (*TokenEndpoint, error) {
	endpoint := &TokenEndpoint{issuedTokens: map[IssuedToken]struct{}{IssuedAccessToken: {}}}
	for index, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil token endpoint config option at index %d", index))
		}
		if err := option(endpoint); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("apply token endpoint config option at index %d: %w", index, err))
		}
	}
	if endpoint.issuerOptionsCallback == nil {
		endpoint.issuerOptionsCallback = func(context.Context, vapi.ScopedPrincipal) (IssuerOptions, error) {
			return IssuerOptions{}, nil
		}
	}

	var err error
	if endpoint.requestAuthenticator == nil {
		endpoint.requestAuthenticator, err = tokenrequest.NewAuthenticator()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create token request authenticator: %w", err))
		}
	}
	if endpoint.issuer == nil {
		endpoint.issuer, err = jwt.NewIssuer()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create JWT issuer: %w", err))
		}
	}
	if endpoint.responseWriter == nil {
		endpoint.responseWriter, err = tokenresponse.NewWriter()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create token response writer: %w", err))
		}
	}
	return endpoint, nil
}

// ServeHTTP authenticates a token request, issues the configured tokens for
// its scoped subject, and writes the OAuth token response.
func (e *TokenEndpoint) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if e == nil || e.requestAuthenticator == nil || e.issuer == nil || e.responseWriter == nil || e.issuerOptionsCallback == nil || len(e.issuedTokens) == 0 {
		http.Error(response, "internal server error", http.StatusInternalServerError)
		return
	}
	if request == nil {
		http.Error(response, "bad request", http.StatusBadRequest)
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	principal, err := e.requestAuthenticator.Authenticate(request.Context(), request)
	if err != nil {
		e.handleError(response, err)
		return
	}
	scopedPrincipal, ok := principal.(vapi.ScopedPrincipal)
	if !ok {
		e.handleError(response, vapi.NewErrorCategory(vapi.ErrPolicyRejected, fmt.Errorf("token request authenticator returned non-scoped principal of type %T", principal)))
		return
	}
	issuerOptions, err := e.issuerOptionsCallback(request.Context(), scopedPrincipal)
	if err != nil {
		e.handleError(response, err)
		return
	}

	tokenResponse := &tokenresponse.TokenResponse{
		TokenType: "Bearer",
		Scope:     strings.Join(scopedPrincipal.GrantedScopes(), " "),
	}
	if _, issue := e.issuedTokens[IssuedAccessToken]; issue {
		options := []jwt.IssuerOption{jwt.WithPrincipal(scopedPrincipal)}
		options = append(options, issuerOptions.AccessToken...)
		tokenResponse.AccessToken, err = e.issuer.Issue(request.Context(), options...)
		if err != nil {
			e.handleError(response, fmt.Errorf("issue access token: %w", err))
			return
		}
	}
	if _, issue := e.issuedTokens[IssuedRefreshToken]; issue {
		options := []jwt.IssuerOption{jwt.WithPrincipal(scopedPrincipal)}
		options = append(options, issuerOptions.RefreshToken...)
		tokenResponse.RefreshToken, err = e.issuer.Issue(request.Context(), options...)
		if err != nil {
			e.handleError(response, fmt.Errorf("issue refresh token: %w", err))
			return
		}
	}
	if _, issue := e.issuedTokens[IssuedIDToken]; issue {
		options := []jwt.IssuerOption{jwt.WithPrincipal(scopedPrincipal)}
		options = append(options, issuerOptions.IDToken...)
		tokenResponse.IdToken, err = e.issuer.Issue(request.Context(), options...)
		if err != nil {
			e.handleError(response, fmt.Errorf("issue ID token: %w", err))
			return
		}
	}
	if err := e.responseWriter.WriteArtifact(request.Context(), response, tokenResponse); err != nil {
		e.handleError(response, err)
	}
}

func (e *TokenEndpoint) handleError(response http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "server_error"
	switch {
	case errors.Is(err, vapi.ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "invalid_client"
	case errors.Is(err, vapi.ErrUnsupported):
		status, code = http.StatusBadRequest, "unsupported_grant_type"
	case errors.Is(err, vapi.ErrPolicyRejected):
		status, code = http.StatusBadRequest, "invalid_grant"
	case errors.Is(err, vapi.ErrMalformed):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, vapi.ErrUnavailable):
		status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
	}
	response.Header().Set("Content-Type", "application/json;charset=UTF-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(struct {
		Error string `json:"error"`
	}{Error: code})
}

var _ http.Handler = &TokenEndpoint{}
