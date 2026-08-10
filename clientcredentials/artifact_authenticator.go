package clientcredentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

type ArtifactAuthenticator struct{ runtimeOptions []ArtifactAuthenticatorOption }
type ArtifactAuthenticatorConfigOption func(*ArtifactAuthenticator) error
type AuthenticateArtifactFunc func(context.Context, *ClientCredentials) (vapi.Principal, error)
type ArtifactAuthenticatorOption func(AuthenticateArtifactFunc) AuthenticateArtifactFunc

func NewArtifactAuthenticator(options ...ArtifactAuthenticatorConfigOption) (*ArtifactAuthenticator, error) {
	a := &ArtifactAuthenticator{}
	for _, option := range options {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil artifact authenticator config option"))
		}
		if err := option(a); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return a, nil
}

func (a *ArtifactAuthenticator) AuthenticateArtifact(ctx context.Context, artifact *ClientCredentials, options ...ArtifactAuthenticatorOption) (vapi.Principal, error) {
	if a == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate client credentials with nil artifact authenticator"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot authenticate nil client credentials"))
	}
	all := append(append(make([]ArtifactAuthenticatorOption, 0, len(a.runtimeOptions)+len(options)), a.runtimeOptions...), options...)
	next := a.authenticateArtifact
	for index := len(all) - 1; index >= 0; index-- {
		if all[index] == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil artifact authenticator option at index %d", index))
		}
		wrapped := all[index](next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("artifact authenticator option at index %d returned nil AuthenticateArtifactFunc", index))
		}
		next = wrapped
	}
	return next(ctx, artifact)
}

func (*ArtifactAuthenticator) authenticateArtifact(_ context.Context, artifact *ClientCredentials) (vapi.Principal, error) {
	return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("no artifact authentication option for client authentication method %q", artifact.AuthMethod))
}

var _ vapi.ArtifactAuthenticator[*ClientCredentials, ArtifactAuthenticatorOption] = &ArtifactAuthenticator{}
