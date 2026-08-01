package jwk

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

const JwkKind = "oauth2:jwk"

type Jwk struct {
	Alg sig.SigAlg
	Key sig.Signer
}

// Kind implements [vapi.Artifacter].
func (j *Jwk) Kind() string {
	return JwkKind
}

var _ vapi.Artifact = &Jwk{}
