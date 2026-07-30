package velesoauth

import (
	"context"
	"net/http"

	"github.com/veles-security/vapi"
	velesapi "github.com/veles-security/vapi"
)

type JwtInjector struct {
	Encoder velesapi.EncodeSchemer[*JwtToken, JwtEncoderOption]
}

type JwtInjectorOption struct {
}

// AddCredentials implements [velesapi.InjectorSchemer].
func (j *JwtInjector) InjectArtifact(ctx context.Context, request *http.Request, artifact *JwtToken, options ...JwtInjectorOption) error {
	raw, err := j.Encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.ErrMalformed
	}
	request.Header.Set("Authorization", "Bearer "+string(raw))
	return nil
}

var _ velesapi.InjectorSchemer[*http.Request, *JwtToken, JwtInjectorOption] = &JwtInjector{}
