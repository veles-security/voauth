package clientcredentials

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

type Authenticator struct {
	reader                vapi.Reader[*http.Request, *ClientCredentials, ReaderOption]
	validator             vapi.Validator[*ClientCredentials, ValidatorOption]
	artifactAuthenticator vapi.ArtifactAuthenticator[*ClientCredentials, ArtifactAuthenticatorOption]
}

type AuthenticatorConfigOption func(*Authenticator) error

func NewAuthenticator(configOptions ...AuthenticatorConfigOption) (*Authenticator, error) {
	authenticator := &Authenticator{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil authenticator config option"))
		}
		if err := option(authenticator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if authenticator.reader == nil {
		reader, err := NewReader()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		authenticator.reader = reader
	}
	if authenticator.validator == nil {
		validator, err := NewValidator()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		authenticator.validator = validator
	}
	if authenticator.artifactAuthenticator == nil {
		artifactAuthenticator, err := NewArtifactAuthenticator()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		authenticator.artifactAuthenticator = artifactAuthenticator
	}
	return authenticator, nil
}

// Authenticate implements [vapi.Authenticator].
func (a *Authenticator) Authenticate(ctx context.Context, request *http.Request) (vapi.Principal, error) {
	if a == nil || a.reader == nil || a.validator == nil || a.artifactAuthenticator == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate client credentials with invalid authenticator configuration"))
	}
	credentials, err := a.reader.ReadArtifact(ctx, request)
	if err != nil {
		if errors.Is(err, vapi.ErrNotApplicable) {
			return nil, err
		}
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	if err := a.validator.Validate(ctx, credentials); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	principal, err := a.artifactAuthenticator.AuthenticateArtifact(ctx, credentials)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client credentials artifact authenticator returned nil principal"))
	}
	return principal, nil
}

var _ vapi.Authenticator[*http.Request] = &Authenticator{}
