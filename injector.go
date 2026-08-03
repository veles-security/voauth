package voauth

import (
	"context"
	"net/http"

	"github.com/veles-security/vapi"
)

type JwtWriter struct {
	encoder vapi.Encoder[*JwtToken, JwtEncoderOption]
}

type JwtWriterOption func(*JwtWriter)

func NewJwtInjector(options ...JwtWriterOption) *JwtWriter {
	injector := &JwtWriter{}
	for _, option := range options {
		option(injector)
	}
	if injector.encoder == nil {
		injector.encoder = NewJwtEncoder()
	}
	return injector
}

// AddCredentials implements [velesapi.Writer].
func (j *JwtWriter) WriteArtifact(ctx context.Context, request *http.Request, artifact *JwtToken, options ...JwtWriterOption) error {
	raw, err := j.encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.ErrMalformed
	}
	request.Header.Set("Authorization", "Bearer "+string(raw))
	return nil
}

var _ vapi.Writer[*http.Request, *JwtToken, JwtWriterOption] = &JwtWriter{}
