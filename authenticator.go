package voauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

type JwtAuthenticator struct {
	tokenExtractor  vapi.Reader[*http.Request, *JwtToken, JwtReaderOption]
	tokenValidator  vapi.Validator[*JwtToken, JwtValidationPolicer]
	principalMapper vapi.PrincipalExtractor[*JwtToken, JwtPrincipalMapper]
}

type JwtAuthenticatorOption func(*JwtAuthenticator)

func NewJwtAuthenticator(
	extractor vapi.Reader[*http.Request, *JwtToken, JwtReaderOption],
	validator vapi.Validator[*JwtToken, JwtValidationPolicer],
	mapper vapi.PrincipalExtractor[*JwtToken, JwtPrincipalMapper],
) *JwtAuthenticator {
	authenticator := &JwtAuthenticator{}
	authenticator.tokenExtractor = extractor
	authenticator.tokenValidator = validator
	authenticator.principalMapper = mapper
	return authenticator
}

// Authenticate implements [vapi.AuthSchemer].
func (j *JwtAuthenticator) Authenticate(ctx context.Context, request *http.Request) (vapi.Principal, error) {
	token, err := j.tokenExtractor.ReadArtifact(ctx, request)
	if err != nil {
		if errors.Is(err, vapi.ErrNotApplicable) {
			return nil, err
		}
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	if err := j.tokenValidator.Validate(ctx, token); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	principal, err := j.principalMapper.ExtractPrincipal(ctx, token)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	return principal, nil
}

var _ vapi.Authenticator[*http.Request] = &JwtAuthenticator{}
