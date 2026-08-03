package jwt

import (
	"context"
	"net/http"

	"github.com/veles-security/vapi"
)

type Writer struct {
	encoder vapi.Encoder[*Token, EncoderOption]
}

type WriterOption func(*Writer)

func NewJwtInjector(options ...WriterOption) *Writer {
	injector := &Writer{}
	for _, option := range options {
		option(injector)
	}
	if injector.encoder == nil {
		injector.encoder = NewJwtEncoder()
	}
	return injector
}

// AddCredentials implements [velesapi.Writer].
func (j *Writer) WriteArtifact(ctx context.Context, request *http.Request, artifact *Token, options ...WriterOption) error {
	raw, err := j.encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.ErrMalformed
	}
	request.Header.Set("Authorization", "Bearer "+string(raw))
	return nil
}

var _ vapi.Writer[*http.Request, *Token, WriterOption] = &Writer{}
