package tokenendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

// IssuerOptionsCallback derives the options used to issue an access token from
// a validated token request. Authentication and authorization policy belong in
// this callback.
type IssuerOptionsCallback func(context.Context, *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error)

// TokenResponseCallback builds the successful token response after the access
// token has been issued. It may add a refresh token, ID token, granted scopes,
// resources, and other response metadata.
type TokenResponseCallback func(context.Context, *tokenrequest.TokenRequest, *jwt.Token) (*tokenresponse.TokenResponse, error)

// TokenEndpointConfigOption configures a TokenEndpoint.
type TokenEndpointConfigOption func(*TokenEndpoint) error

// TokenEndpoint implements an OAuth 2.0 token endpoint HTTP handler.
type TokenEndpoint struct {
	requestReader                     *tokenrequest.Reader
	requestReaderOptions              []tokenrequest.ReaderConfigOption
	clientCredentialsValidator        *clientcredentials.Validator
	clientCredentialsValidatorOptions []clientcredentials.ValidatorConfigOption
	requestValidator                  *tokenrequest.Validator
	requestValidatorOptions           []tokenrequest.ValidatorConfigOption
	issuer                            *jwt.Issuer
	issuerOptions                     []jwt.IssuerConfigOption
	issuerOptionsCallback             IssuerOptionsCallback
	responseWriter                    *tokenresponse.Writer
	responseWriterOptions             []tokenresponse.WriterConfigOption
	tokenResponseCallback             TokenResponseCallback
}

// New constructs a token endpoint and all of its dependent components.
func New(configOptions ...TokenEndpointConfigOption) (*TokenEndpoint, error) {
	endpoint := &TokenEndpoint{
		tokenResponseCallback: func(_ context.Context, request *tokenrequest.TokenRequest, accessToken *jwt.Token) (*tokenresponse.TokenResponse, error) {
			return &tokenresponse.TokenResponse{
				AccessToken: accessToken,
				TokenType:   "Bearer",
				Scope:       request.Scope,
			}, nil
		},
	}
	for index, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil token endpoint config option at index %d", index))
		}
		if err := option(endpoint); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("apply token endpoint config option at index %d: %w", index, err))
		}
	}
	if endpoint.issuerOptionsCallback == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("missing issuer options callback"))
	}

	var err error
	endpoint.requestReader, err = tokenrequest.NewReader(endpoint.requestReaderOptions...)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create token request reader: %w", err))
	}
	endpoint.clientCredentialsValidator, err = clientcredentials.NewValidator(endpoint.clientCredentialsValidatorOptions...)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create client credentials validator: %w", err))
	}
	requestValidatorOptions := append(
		slices.Clone(endpoint.requestValidatorOptions),
		tokenrequest.WithClientCredentialsValidator(endpoint.clientCredentialsValidator),
	)
	endpoint.requestValidator, err = tokenrequest.NewValidator(requestValidatorOptions...)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create token request validator: %w", err))
	}
	endpoint.issuer, err = jwt.NewIssuer(endpoint.issuerOptions...)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create JWT issuer: %w", err))
	}
	endpoint.responseWriter, err = tokenresponse.NewWriter(endpoint.responseWriterOptions...)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create token response writer: %w", err))
	}

	return endpoint, nil
}

// ServeHTTP reads and validates a token request, applies application policy,
// issues an access token, and writes an OAuth token response.
func (e *TokenEndpoint) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if e == nil || e.requestReader == nil || e.requestValidator == nil || e.issuer == nil || e.responseWriter == nil || e.issuerOptionsCallback == nil || e.tokenResponseCallback == nil {
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

	tokenRequest, err := e.requestReader.ReadArtifact(request.Context(), request)
	if err != nil {
		e.handleError(response, err)
		return
	}
	err = e.requestValidator.Validate(request.Context(), tokenRequest)
	if err != nil {
		e.handleError(response, err)
		return
	}

	issuerOptions, err := e.issuerOptionsCallback(request.Context(), tokenRequest)
	if err != nil {
		e.handleError(response, err)
		return
	}

	accessToken, err := e.issuer.Issue(request.Context(), issuerOptions...)
	if err != nil {
		e.handleError(response, err)
		return
	}

	tokenResponse, err := e.tokenResponseCallback(request.Context(), tokenRequest, accessToken)
	if err != nil {
		e.handleError(response, err)
		return
	} else if tokenResponse == nil {
		err = vapi.NewErrorCategory(vapi.ErrInternal, errors.New("token response callback returned nil response"))
		e.handleError(response, err)
		return
	}

	err = e.responseWriter.WriteArtifact(request.Context(), response, tokenResponse)
	if err != nil {
		e.handleError(response, err)
		return
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
