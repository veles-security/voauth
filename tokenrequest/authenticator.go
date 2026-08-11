package tokenrequest

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

type Authenticator struct {
	reader    vapi.Reader[*http.Request, *TokenRequest, ReaderOption]
	validator vapi.Validator[*TokenRequest, ValidatorOption]
	resolver  vapi.Resolver[*TokenRequest, ResolverOption]
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
	if authenticator.resolver == nil {
		resolver, err := NewResolver()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		authenticator.resolver = resolver
	}
	return authenticator, nil
}

// Authenticate implements [vapi.Authenticator].
func (a *Authenticator) Authenticate(ctx context.Context, request *http.Request) (vapi.Principal, error) {
	if a == nil || a.reader == nil || a.validator == nil || a.resolver == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate token request with invalid authenticator configuration"))
	}

	artifact, err := a.reader.ReadArtifact(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := a.validator.Validate(ctx, artifact); err != nil {
		return nil, err
	}
	principal, err := a.resolver.Resolve(ctx, artifact)
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("token request resolver returned nil principal"))
	}
	return principal, nil
}

var _ vapi.Authenticator[*http.Request] = &Authenticator{}
