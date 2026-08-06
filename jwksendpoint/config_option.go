package jwksendpoint

import (
	"fmt"
	"slices"

	"github.com/veles-security/voauth/jwks"
)

// WithJwksOption forwards options to the JSON Web Key Set constructed by the
// endpoint.
func WithJwksOption(options ...jwks.JwksOption) JwksEndpointConfigOption {
	return func(endpoint *JwksEndpoint) error {
		for index, option := range options {
			if option == nil {
				return fmt.Errorf("nil JWKS option at index %d", index)
			}
		}
		endpoint.setOptions = append(endpoint.setOptions, slices.Clone(options)...)
		return nil
	}
}

// WithJwksWriterOption forwards configuration options to the JWKS writer
// constructed by the endpoint.
func WithJwksWriterOption(options ...jwks.WriterConfigOption) JwksEndpointConfigOption {
	return func(endpoint *JwksEndpoint) error {
		endpoint.writerOptions = append(endpoint.writerOptions, slices.Clone(options)...)
		return nil
	}
}
