package jwk

import (
	"crypto"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

const JwkKind = "oauth2:jwk"

type Jwk struct {
	sig.SignVerifier
}

func NewJwk(alg sig.SigAlg, key crypto.PublicKey, kid string) *Jwk {
	return &Jwk{
		sig.SignVerifier{
			Kid: kid,
			Alg: alg,
			Key: key,
		},
	}
}

// Kind implements [vapi.Artifacter].
func (j *Jwk) Kind() string {
	return JwkKind
}

var _ vapi.Artifact = &Jwk{}
