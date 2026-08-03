package jwks

import "github.com/veles-security/voauth/jwk"

const JwksKind = "oauth2:jwks"

type Jwks struct {
	Keys []jwk.Jwk
}

func (j *Jwks) Kind() string {
	return JwksKind
}
