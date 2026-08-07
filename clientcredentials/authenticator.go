package clientcredentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

type Authenticator struct {
	authCallbacks map[string]AuthCallback
	validator     vapi.Validator[*ClientCredentials, ValidatorOption]
}

type AuthCallback func(ctx context.Context, credentials *ClientCredentials) (vapi.Principal, error)

type AuthenticatorConfigOption func(*Authenticator) error

func NewAuthenticator(configOptions ...AuthenticatorConfigOption) (*Authenticator, error) {
	authenticator := &Authenticator{authCallbacks: make(map[string]AuthCallback)}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil authenticator config option"))
		}
		if err := option(authenticator); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if len(authenticator.authCallbacks) == 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("no client credentials authentication callbacks"))
	}
	return authenticator, nil
}

// Authenticate implements [vapi.Authenticator].
func (a *Authenticator) Authenticate(ctx context.Context, credentials *ClientCredentials) (vapi.Principal, error) {
	if a == nil || a.authCallbacks == nil || len(a.authCallbacks) == 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate client credentials with invalid authenticator configuration"))
	}
	if credentials == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot authenticate nil client credentials"))
	}
	if a.validator != nil {
		if err := a.validator.Validate(ctx, credentials); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("validate client credentials: %w", err))
		}
	}
	callback, ok := a.authCallbacks[credentials.AuthMethod]
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("no authentication callback for client authentication method %q", credentials.AuthMethod))
	}
	principal, err := callback(ctx, credentials)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("authenticate client credentials using method %q: %w", credentials.AuthMethod, err))
	}
	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("authentication callback for client authentication method %q returned nil principal", credentials.AuthMethod))
	}
	return principal, nil
}

var _ vapi.Authenticator[*ClientCredentials] = &Authenticator{}
