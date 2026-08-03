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
		return fmt.Errorf("cannot write JWKS to HttpResposne with nil JWKS encoder")
	}
	payload, err := i.encoder.Encode(ctx, artifact)
	if err != nil {
		return err
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     carrier.Header(),
	}
	for _, option := range options {
		if err := option.Apply(artifact, response); err != nil {
			return err
		}
	}

	response.Header.Set("Content-Type", "application/jwk-set+json")
	carrier.WriteHeader(response.StatusCode)
	_, err = carrier.Write(payload)
	return err
}

var _ vapi.Writer[http.ResponseWriter, *Jwks, WriterOption] = &Writer{}
