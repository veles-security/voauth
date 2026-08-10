package tokenrequest

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

type Authenticator struct {
	authCallbacks               map[string]AuthCallback
	validator                   vapi.Validator[*TokenRequest, ValidatorOption]
	clientArtifactAuthenticator vapi.ArtifactAuthenticator[*clientcredentials.ClientCredentials, clientcredentials.ArtifactAuthenticatorOption]
}

type AuthenticatorConfigOption func(*Authenticator) error

// AuthCallback authenticates a token request for a grant type and returns the
// principal for which the token will be issued. clientPrincipal is nil when no
// client authenticator is configured.
type AuthCallback func(ctx context.Context, request *TokenRequest, clientPrincipal vapi.Principal) (vapi.Principal, error)

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
	if len(authenticator.authCallbacks) == 0 && authenticator.clientArtifactAuthenticator == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("no token request authentication callbacks or client authenticator"))
	}
	return authenticator, nil
}

// Authenticate implements [vapi.Authenticator].
func (a *Authenticator) Authenticate(ctx context.Context, request *TokenRequest) (vapi.Principal, error) {
	if a == nil || a.authCallbacks == nil || (len(a.authCallbacks) == 0 && a.clientArtifactAuthenticator == nil) {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot authenticate token request with invalid authenticator configuration"))
	}
	if request == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot authenticate nil token request"))
	}
	if a.validator != nil {
		if err := a.validator.Validate(ctx, request); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("validate token request: %w", err))
		}
	}

	var clientPrincipal vapi.Principal
	if a.clientArtifactAuthenticator != nil {
		principal, err := a.clientArtifactAuthenticator.AuthenticateArtifact(ctx, &request.ClientCredentials)
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("authenticate client: %w", err))
		}
		if principal == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client authenticator returned nil principal"))
		}
		clientPrincipal = principal
	}

	callback, ok := a.authCallbacks[request.GrantType]
	if !ok {
		if request.GrantType == ClientCredentialsGrantType && clientPrincipal != nil {
			return clientPrincipal, nil
		}
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("no authentication callback for grant type %q", request.GrantType))
	}
	principal, err := callback(ctx, request, clientPrincipal)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("authenticate token request for grant type %q: %w", request.GrantType, err))
	}
	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("authentication callback for grant type %q returned nil principal", request.GrantType))
	}
	return principal, nil
}

var _ vapi.Authenticator[*TokenRequest] = &Authenticator{}
