package jwt

import "github.com/veles-security/vapi/sig"

func WithSigner(signer *sig.Signer) IssuerConfigOption {
	return func(issuer *Issuer) error {
		issuer.signer = signer
		return nil
	}
}
