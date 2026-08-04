package tokenrequest

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/token"
)

const TokenRequestKind = "oauth2:token_request" // #nosec G101 -- token request kind identifier, not a credential

type TokenRequest struct {
	// GrantType selects the OAuth 2.0 grant being requested. It is used by all grant types.
	GrantType string
	// ClientCredentials authenticates the client. It is used by all grant types when client authentication is required.
	ClientCredentials clientcredentials.ClientCredentials
	// Code is the authorization code received from the authorization server. It is used by the authorization_code grant type.
	Code string
	// RedirectUri is the redirect URI used in the authorization request. It is used by the authorization_code grant type when one was supplied during authorization.
	RedirectUri string
	// CodeVerifier is the PKCE verifier associated with the authorization code. It is used by the authorization_code grant type when PKCE was used.
	CodeVerifier string
	// Username is the resource owner's username. It is used by the password grant type.
	Username string
	// Password is the resource owner's password. It is used by the password grant type.
	Password string
	// RefreshToken is the refresh token issued by the authorization server. It is used by the refresh_token grant type.
	RefreshToken token.AnyToken
	// Scope limits the requested access. It is used by the password, client_credentials, and refresh_token grant types.
	Scope string
	// DeviceCode is the code issued by the device authorization endpoint. It is used by the urn:ietf:params:oauth:grant-type:device_code grant type.
	DeviceCode string
	// Assertion contains a bearer assertion. It is used by the urn:ietf:params:oauth:grant-type:jwt-bearer and urn:ietf:params:oauth:grant-type:saml2-bearer grant types.
	Assertion token.AnyToken
}

// Kind implements [vapi.Artifact].
func (t *TokenRequest) Kind() string {
	return TokenRequestKind
}

var _ vapi.Artifact = &TokenRequest{}
