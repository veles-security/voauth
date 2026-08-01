package jwks

import "github.com/veles-security/voauth/jwk"

type JwksRepresentation struct {
	Keys []jwk.JwkRepresentation `json:"keys"`
}
