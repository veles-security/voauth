package tokenresponse

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

const TokenResponseKind = "oauth2:token_response" // #nosec G101 -- token response kind identifier, not a credential

type TokenResponse struct {
	AccessToken  token.AnyToken
	RefreshToken token.AnyToken
	IdToken      token.AnyToken
	Scope        string
	Resources    []string
}

// Kind implements [vapi.Artifact].
func (t *TokenResponse) Kind() string {
	return TokenResponseKind
}

var _ vapi.Artifact = &TokenResponse{}
