package tokenrequest

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
)

const TokenRequestKind = "oauth2:token_request"

type TokenRequest struct {
	GrantType         string
	ClientCredentials clientcredentials.ClientCredentials
}

// Kind implements [vapi.Artifact].
func (t *TokenRequest) Kind() string {
	return TokenRequestKind
}

var _ vapi.Artifact = &TokenRequest{}
