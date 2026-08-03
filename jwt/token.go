package jwt

import (
	"time"

	velesapi "github.com/veles-security/vapi"
	"github.com/veles-security/voauth"
)

const (
	TokenKind        = "oauth2:token"         // #nosec G101 -- token kind identifier, not a credential
	IDTokenKind      = "oauth2:id_token"      // #nosec G101 -- token kind identifier, not a credential
	AccessTokenKind  = "oauth2:access_token"  // #nosec G101 -- token kind identifier, not a credential
	RefreshTokenKind = "oauth2:refresh_token" // #nosec G101 -- token kind identifier, not a credential

	TokenJwtType = "jwt"
)

type Token struct {
	iat       time.Time
	Header    map[string]string
	Claims    Cliams
	signature []byte
}

// TokenType implements [voauth.Token].
func (j *Token) TokenType() string {
	return TokenJwtType
}

// Kind implements [velesapi.Artifacter].
func (j *Token) Kind() string {
	return TokenKind
}

type IDToken struct{ Token }

// Kind implements [velesapi.Artifacter].
func (i *IDToken) Kind() string {
	return IDTokenKind
}

type AccessToken struct{ Token }

// Kind implements [velesapi.Artifacter].
func (a *AccessToken) Kind() string {
	return AccessTokenKind
}

type RefreshToken struct{ Token }

// Kind implements [velesapi.Artifacter].
func (r *RefreshToken) Kind() string {
	return RefreshTokenKind
}

var _ velesapi.Artifact = &Token{}
var _ velesapi.Artifact = &IDToken{}
var _ velesapi.Artifact = &AccessToken{}
var _ velesapi.Artifact = &RefreshToken{}
var _ voauth.Token = &Token{}
