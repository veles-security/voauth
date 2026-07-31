package voauth

import (
	"context"
	"errors"
	"net/http"

	velesapi "github.com/veles-security/vapi"
)

type JwtAuthenticator struct {
	tokenExtractor  velesapi.ExtractorSchemer[*http.Request, *JwtToken, JwtExtractorOption]
	tokenValidator  velesapi.ValidationSchemer[*JwtToken, JwtValidationPolicer]
	principalMapper velesapi.PrincipalSchemer[*JwtToken, JwtPrincipalMapper]
}

type JwtAuthenticatorOption func(*JwtAuthenticator)

func NewJwtAuthenticator(options ...JwtAuthenticatorOption) *JwtAuthenticator {
	authenticator := &JwtAuthenticator{}
	for _, option := range options {
		option(authenticator)
	}
	if authenticator.tokenExtractor == nil {
		authenticator.tokenExtractor = NewJwtExtractor()
	}
	return authenticator
}

// Authenticate implements [velesapi.AuthSchemer].
func (j *JwtAuthenticator) Authenticate(ctx context.Context, request *http.Request) (velesapi.Principaler, error) {
	token, err := j.tokenExtractor.ExtractArtifact(ctx, request)
	if err != nil {
		if errors.Is(err, velesapi.ErrNotApplicable) {
			return nil, err
		}
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, err)
	}
	if err := j.tokenValidator.Validate(ctx, token); err != nil {
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, err)
	}
	principal, err := j.principalMapper.ExtractPrincipal(ctx, token)
	if err != nil {
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, err)
	}
	return principal, nil
}

var _ velesapi.AuthSchemer[*http.Request] = &JwtAuthenticator{}
