package jwt

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

type Authenticator struct {
	tokenExtractor  vapi.Reader[*http.Request, *Token, ReaderOption]
	tokenValidator  vapi.Validator[*Token, ValidationPolicer]
	principalMapper vapi.PrincipalExtractor[*Token, JwtPrincipalMapper]
}

type AuthenticatorOption func(*Authenticator)

func NewAuthenticator(
	extractor vapi.Reader[*http.Request, *Token, ReaderOption],
	validator vapi.Validator[*Token, ValidationPolicer],
	mapper vapi.PrincipalExtractor[*Token, JwtPrincipalMapper],
) *Authenticator {
	authenticator := &Authenticator{}
	authenticator.tokenExtractor = extractor
	authenticator.tokenValidator = validator
	authenticator.principalMapper = mapper
	return authenticator
}

// Authenticate implements [vapi.AuthSchemer].
func (j *Authenticator) Authenticate(ctx context.Context, request *http.Request) (vapi.Principal, error) {
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

var _ vapi.Authenticator[*http.Request] = &Authenticator{}
