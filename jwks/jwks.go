package jwks

import (
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/jwk"
	"github.com/veles-security/voauth/jwt"
)

const JwksKind = "oauth2:jwks"

type Jwks struct {
	Keys []jwk.Jwk
}

type JwksOption func(*Jwks)

func WithKeyFromSigner(signer *sig.Signer) JwksOption {
	return func(j *Jwks) {
		j.Keys = append(j.Keys, *jwk.NewJwk(signer.Alg, signer.Key.Public(), signer.Kid))
	}
}

func WithKeyFromJwtSigner(signer *jwt.Signer) JwksOption {
	return func(j *Jwks) {
		j.Keys = append(j.Keys, *jwk.NewJwk(signer.Alg(), signer.Public(), signer.Kid()))
	}
}

func NewJwks(options ...JwksOption) *Jwks {
	j := &Jwks{
		Keys: []jwk.Jwk{},
	}
	for _, option := range options {
		option(j)
	}
	return j
}

func (j *Jwks) Kind() string {
	return JwksKind
}
