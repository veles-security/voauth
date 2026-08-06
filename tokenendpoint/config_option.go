package tokenendpoint

import (
	"errors"
	"slices"

	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

// WithClientCredentialsValidatorOption forwards configuration options to the
// client credentials validator constructed by the endpoint.
func WithClientCredentialsValidatorOption(options ...clientcredentials.ValidatorConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		endpoint.clientCredentialsValidatorOptions = append(endpoint.clientCredentialsValidatorOptions, slices.Clone(options)...)
		return nil
	}
}

// WithTokenRequestReaderOption forwards configuration options to the token
// request reader constructed by the endpoint.
func WithTokenRequestReaderOption(options ...tokenrequest.ReaderConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		endpoint.requestReaderOptions = append(endpoint.requestReaderOptions, slices.Clone(options)...)
		return nil
	}
}

// WithTokenRequestValidatorOption forwards configuration options to the token
// request validator constructed by the endpoint.
func WithTokenRequestValidatorOption(options ...tokenrequest.ValidatorConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		endpoint.requestValidatorOptions = append(endpoint.requestValidatorOptions, slices.Clone(options)...)
		return nil
	}
}

// WithJWTIssuerOption forwards configuration options to the JWT issuer
// constructed by the endpoint.
func WithJWTIssuerOption(options ...jwt.IssuerConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		endpoint.issuerOptions = append(endpoint.issuerOptions, slices.Clone(options)...)
		return nil
	}
}

// WithTokenResponseWriterOption forwards configuration options to the token
// response writer constructed by the endpoint.
func WithTokenResponseWriterOption(options ...tokenresponse.WriterConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		endpoint.responseWriterOptions = append(endpoint.responseWriterOptions, slices.Clone(options)...)
		return nil
	}
}

// WithIssuerOptionsCallback configures the application policy invoked after a
// request is validated and before its access token is issued.
func WithIssuerOptionsCallback(callback IssuerOptionsCallback) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if callback == nil {
			return errors.New("nil issuer options callback")
		}
		endpoint.issuerOptionsCallback = callback
		return nil
	}
}

// WithTokenResponseCallback configures how an issued access token is turned
// into the successful OAuth token response.
func WithTokenResponseCallback(callback TokenResponseCallback) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if callback == nil {
			return errors.New("nil token response callback")
		}
		endpoint.tokenResponseCallback = callback
		return nil
	}
}
