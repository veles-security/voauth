package velesoauth

import (
	"context"
	"errors"
	"net/http"

	velesapi "github.com/veles-security/vapi"
)

type JwtAuthenticator struct {
	TokenExtractor  velesapi.ExtractorSchemer[*http.Request, *JwtToken, JwtExtractorOption]
	TokenValidator  velesapi.ValidationSchemer[*JwtToken, JwtValidationPolicer]
	PrincipalMapper velesapi.PrincipalSchemer[*JwtToken, JwtPrincipalMapper]
}

// Authenticate implements [velesapi.AuthSchemer].
func (j *JwtAuthenticator) Authenticate(ctx context.Context, request *http.Request) (velesapi.Principaler, error) {
	token, err := j.TokenExtractor.ExtractArtifact(ctx, request)
	if err != nil {
		if errors.Is(err, velesapi.ErrNotApplicable) {
			return nil, err
		}
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, err)
	}
	if err := j.TokenValidator.Validate(ctx, token); err != nil {
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, err)
	}
	principal, err := j.PrincipalMapper.ExtractPrincipal(ctx, token)
	if err != nil {
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, err)
	}
	return principal, nil
}

var _ velesapi.AuthSchemer[*http.Request] = &JwtAuthenticator{}
