package jwt

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
)

type ArtifactAuthenticator struct {
	runtimeOptions []ArtifactAuthenticatorOption
}

type ArtifactAuthenticatorConfigOption func(*ArtifactAuthenticator) error

type AuthenticateArtifactFunc func(ctx context.Context, artifact *Token) (vapi.Principal, error)

type ArtifactAuthenticatorOption func(next AuthenticateArtifactFunc) AuthenticateArtifactFunc

func NewArtifactAuthenticator(configOptions ...ArtifactAuthenticatorConfigOption) (*ArtifactAuthenticator, error) {
	authenticator := &ArtifactAuthenticator{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil artifact authenticator config option"))
		}
		if err := option(authenticator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return authenticator, nil
}

// AuthenticateArtifact implements [vapi.ArtifactAuthenticator].
func (a *ArtifactAuthenticator) AuthenticateArtifact(ctx context.Context, artifact *Token, options ...ArtifactAuthenticatorOption) (vapi.Principal, error) {
	if a == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate JWT with nil artifact authenticator"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot authenticate nil JWT"))
	}

	allOptions := make([]ArtifactAuthenticatorOption, 0, len(a.runtimeOptions)+len(options))
	allOptions = append(allOptions, a.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := a.authenticateArtifact
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil artifact authenticator option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("artifact authenticator option at index %d returned nil AuthenticateArtifactFunc", index))
		}
		next = wrapped
	}

	return next(ctx, artifact)
}

func (a *ArtifactAuthenticator) authenticateArtifact(_ context.Context, artifact *Token) (vapi.Principal, error) {
	issuer, _ := artifact.Claims["iss"].(string)
	subject, _ := artifact.Claims["sub"].(string)
	principal := sub.NewBasePrincipal(issuer, subject, "oauth2:principal")
	return principal, nil
}

var _ vapi.ArtifactAuthenticator[*Token, ArtifactAuthenticatorOption] = &ArtifactAuthenticator{}
