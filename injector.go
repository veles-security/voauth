package velesoauth

import (
	"context"
	"net/http"

	velesapi "github.com/veles-security/vapi"
)

type JwtInjector struct {
}

type JwtInjectorOption struct {
}

// AddCredentials implements [velesapi.InjectorSchemer].
func (j *JwtInjector) InjectArtifact(ctx context.Context, request *http.Request, artifact *JwtToken, options ...JwtInjectorOption) error {
	request.Header.Set("Authorization", "Bearer "+string(artifact.raw))
	return nil
}

var _ velesapi.InjectorSchemer[*http.Request, *JwtToken, JwtInjectorOption] = &JwtInjector{}
