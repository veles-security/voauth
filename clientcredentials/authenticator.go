package clientcredentials

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
)

type Authenticator struct {
	reader    vapi.Reader[*http.Request, *ClientCredentials, ReaderOption]
	validator vapi.Validator[*ClientCredentials, ValidatorOption]
	resolver  vapi.Resolver[*ClientCredentials, ResolverOption]
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
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate client credentials with invalid authenticator configuration"))
	}

	// Read
	credentials, err := a.reader.ReadArtifact(ctx, request)
	if err != nil {
		if errors.Is(err, vapi.ErrNotApplicable) {
			return nil, err
		}
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}

	// Validate
	if err := a.validator.Validate(ctx, credentials); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}

	// Decode
	principal, err := a.resolver.Resolve(ctx, credentials)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, err)
	}

	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client credentials resolver returned nil principal"))
	}
	return principal, nil
}

var _ vapi.Authenticator[*http.Request] = &Authenticator{}
