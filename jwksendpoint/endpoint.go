package jwksendpoint

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwks"
)

// JwksEndpointConfigOption configures a JwksEndpoint.
type JwksEndpointConfigOption func(*JwksEndpoint) error

// JwksEndpoint serves a JSON Web Key Set over HTTP.
type JwksEndpoint struct {
	set           *jwks.Jwks
	setOptions    []jwks.JwksOption
	writer        *jwks.Writer
	writerOptions []jwks.WriterConfigOption
}

// New constructs a JWKS endpoint and its dependent components.
func New(configOptions ...JwksEndpointConfigOption) (*JwksEndpoint, error) {
	endpoint := &JwksEndpoint{}
	for index, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil JWKS endpoint config option at index %d", index))
		}
		if err := option(endpoint); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("apply JWKS endpoint config option at index %d: %w", index, err))
		}
	}

	endpoint.set = jwks.NewJwks(endpoint.setOptions...)
	if endpoint.set == nil || len(endpoint.set.Keys) == 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("JWKS endpoint requires at least one key"))
	}
	var err error
	endpoint.writer, err = jwks.NewWriter(endpoint.writerOptions...)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create JWKS writer: %w", err))
	}

	return endpoint, nil
}

// ServeHTTP writes the endpoint's JSON Web Key Set.
func (e *JwksEndpoint) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if e == nil || e.set == nil || e.writer == nil {
		http.Error(response, "internal server error", http.StatusInternalServerError)
		return
	}
	if request == nil {
		http.Error(response, "bad request", http.StatusBadRequest)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := e.writer.WriteArtifact(request.Context(), response, e.set); err != nil {
		http.Error(response, "internal server error", http.StatusInternalServerError)
	}
}

var _ http.Handler = &JwksEndpoint{}
