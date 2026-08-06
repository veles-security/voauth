package clientcredentials

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

const ClientCredentialsKind = "oauth2:client_credentials" // #nosec G101 -- client credentials kind identifier, not a credential

const (
	ClientSecretBasicAuthMethod = "client_secret_basic" // #nosec G101 -- client credentials auth method identifier, not a credential
	ClientSecretPostAuthMethod  = "client_secret_post"  // #nosec G101 -- client credentials auth method identifier, not a credential
	PrivateKeyJwtAuthMethod     = "private_key_jwt"     // #nosec G101 -- client credentials auth method identifier, not a credential
)

type ClientCredentials struct {
	AuthMethod          string
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
