package voauth

import (
	"context"
	"net/http"

	"github.com/veles-security/vapi"
)

type JwtInjector struct {
	encoder vapi.Encoder[*JwtToken, JwtEncoderOption]
}

type JwtInjectorOption func(*JwtInjector)

func NewJwtInjector(options ...JwtInjectorOption) *JwtInjector {
	injector := &JwtInjector{}
	for _, option := range options {
		option(injector)
	}
	if injector.encoder == nil {
		injector.encoder = NewJwtEncoder()
	}
	return injector
}

// AddCredentials implements [velesapi.InjectorSchemer].
func (j *JwtInjector) InjectArtifact(ctx context.Context, request *http.Request, artifact *JwtToken, options ...JwtInjectorOption) error {
	raw, err := j.encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.ErrMalformed
	}
	request.Header.Set("Authorization", "Bearer "+string(raw))
	return nil
}

var _ vapi.Injector[*http.Request, *JwtToken, JwtInjectorOption] = &JwtInjector{}
