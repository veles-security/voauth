package clientcredentials

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth"
)

const ClientCredentialsKind = "oauth2:client_credentials"

type ClientCredentials struct {
	ClientId            string
	ClientSecret        string
	ClientAssertionType string
	ClientAssertion     voauth.Token
}

// Kind implements [vapi.Artifact].
func (t *ClientCredentials) Kind() string {
	return ClientCredentialsKind
}

var _ vapi.Artifact = &ClientCredentials{}
