package jwks

import (
	"context"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
)

type Writer struct {
	encoder vapi.Encoder[*Jwks, EncoderOption]
}

type WriterOption interface {
	Configure(*Writer)
	Apply(*Jwks, *http.Response) error
}

func NewWriter(options ...WriterOption) *Writer {
	injector := &Writer{}
	for _, option := range options {
		option.Configure(injector)
	}
	if injector.encoder == nil {
		injector.encoder = NewEncoder()
	}
	return injector
}

func (i *Writer) WriteArtifact(ctx context.Context, carrier http.ResponseWriter, artifact *Jwks, options ...WriterOption) error {
	if i.encoder == nil {
		return fmt.Errorf("cannot write JWKS response with nil JWKS encoder")
	}

	payload, err := i.encoder.Encode(ctx, artifact)
	if err != nil {
		return fmt.Errorf("encode JWKS: %w", err)
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     carrier.Header(),
	}

	for _, option := range options {
		if err := option.Apply(artifact, response); err != nil {
			return fmt.Errorf("apply writer option: %w", err)
		}
	}

	response.Header.Set("Content-Type", "application/jwk-set+json")
	response.Header.Set("X-Content-Type-Options", "nosniff")

	carrier.WriteHeader(response.StatusCode)

	// payload is JSON produced by the trusted JWKS encoder, not HTML.
	_, err = carrier.Write(payload) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	if err != nil {
		return fmt.Errorf("write JWKS response: %w", err)
	}

	return nil
}

var _ vapi.Writer[http.ResponseWriter, *Jwks, WriterOption] = &Writer{}
