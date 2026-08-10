package jwt

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

type Authenticator struct {
	reader    vapi.Reader[*http.Request, *Token, ReaderOption]
	validator vapi.Validator[*Token, ValidatorOption]
	resolver  vapi.Resolver[*Token, ResolverOption]
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

// Authenticate implements [vapi.AuthSchemer].
func (j *Authenticator) Authenticate(ctx context.Context, request *http.Request) (vapi.Principal, error) {
	token, err := j.reader.ReadArtifact(ctx, request)
	if err != nil {
		if errors.Is(err, vapi.ErrNotApplicable) {
			return nil, err
		}
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	if err := j.validator.Validate(ctx, token); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	principal, err := j.resolver.Resolve(ctx, token)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}
	return principal, nil
}

var _ vapi.Authenticator[*http.Request] = &Authenticator{}
