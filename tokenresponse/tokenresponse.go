package tokenresponse

import (
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

const TokenResponseKind = "oauth2:token_response" // #nosec G101 -- token response kind identifier, not a credential

// TokenResponse represents a successful OAuth 2.0 token endpoint response as
// defined by RFC 6749, Section 5.1. It also supports the issued_token_type
// parameter from RFC 8693, Section 2.2.1, the resource parameter from RFC 8707,
// and the id_token parameter from OpenID Connect Core 1.0, Section 3.1.3.3.
type TokenResponse struct {
	// TokenType identifies how the access token is used, such as "Bearer".
	TokenType string
	// AccessToken is the token issued by the authorization server.
	AccessToken token.AnyToken
	// RefreshToken is used to obtain a new access token.
	RefreshToken token.AnyToken
	// IdToken contains the OpenID Connect ID token, when one was issued.
	IdToken token.AnyToken
	// ExpiresIn is the access token lifetime. Zero means unspecified.
	ExpiresIn time.Duration
	// Scope is the space-delimited scope granted to the access token.
	Scope string
	// IssuedTokenType identifies the type of token issued by a token exchange.
	IssuedTokenType string
	// Resources identifies the protected resources for which the token is valid.
	Resources []string
}

// Kind implements [vapi.Artifact].
func (t *TokenResponse) Kind() string {
	return TokenResponseKind
}

var _ vapi.Artifact = &TokenResponse{}
