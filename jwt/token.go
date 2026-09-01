package jwt

import (
	"time"

	velesapi "github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

const (
	TokenKind = "oauth2:token" // #nosec G101 -- token kind identifier, not a credential
	TokenType = "jwt"
)

type Token struct {
	iat       time.Time
	Header    map[string]string
	Claims    Cliams
	signature []byte
}

// TokenType implements [voauth.AnyToken].
func (j *Token) TokenType() string {
	return TokenType
}

// Kind implements [velesapi.Artifacter].
func (j *Token) Kind() string {
	return TokenKind
}

var _ velesapi.Artifact = &Token{}
var _ token.AnyToken = &Token{}
