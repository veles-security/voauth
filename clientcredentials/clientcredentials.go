package clientcredentials

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

const ClientCredentialsKind = "oauth2:client_credentials" // #nosec G101 -- client credentials kind identifier, not a credential

type ClientCredentials struct {
	ClientId            string
	ClientSecret        string
	ClientAssertionType string
	ClientAssertion     token.AnyToken
}

// Kind implements [vapi.Artifact].
func (t *ClientCredentials) Kind() string {
	return ClientCredentialsKind
}

var _ vapi.Artifact = &ClientCredentials{}
