package jwks

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
)

type Writer struct {
	encoder vapi.Encoder[*Jwks, EncoderOption]
}

type WriterConfigOption func(*Writer) error

type WriteFunc func(ctx context.Context, carrierWriter http.ResponseWriter, artifact *Jwks) error

type WriterOption func(next WriteFunc) WriteFunc

func NewWriter(configOptions ...WriterConfigOption) (*Writer, error) {
	writer := &Writer{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil writer config option"))
		}
		if err := option(writer); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if writer.encoder == nil {
		writer.encoder = NewEncoder()
	}
	return writer, nil
}

func (w *Writer) WriteArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *Jwks, options ...WriterOption) error {
	if w.encoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("cannot write JWKS response with nil JWKS encoder"))
	}
	if artifact.Keys == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("cannot write JWKS response with nil Keys"))
	}
	if len(artifact.Keys) == 0 {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("cannot write JWKS response with no Keys"))
	}

	next := w.writeArtifact

	for index := len(options) - 1; index >= 0; index-- {
		if options[index] != nil {
			option := options[index]
			if option == nil {
				return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil writer option at index %d", index))
			}
			wrapped := option(next)
			if wrapped == nil {
				return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("writer option at index %d returned nil WriteFunc", index))
			}
			next = wrapped
		}
	}

	return next(ctx, carrierWriter, artifact)
}

func (w *Writer) writeArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *Jwks) error {
	payload, err := w.encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWKS: %w", err))
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     carrierWriter.Header(),
	}

	response.Header.Set("Content-Type", "application/jwk-set+json")
	response.Header.Set("X-Content-Type-Options", "nosniff")

	carrierWriter.WriteHeader(response.StatusCode)

	// payload is JSON produced by the trusted JWKS encoder, not HTML.
	_, err = carrierWriter.Write(payload) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("write JWKS response: %w", err))
	}

	return nil
}

var _ vapi.Writer[http.ResponseWriter, *Jwks, WriterOption] = &Writer{}
