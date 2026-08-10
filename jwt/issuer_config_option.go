package jwt

import "github.com/veles-security/vapi/sig"

// WithIssuerRuntimeOptions configures issuer options that are applied to every
// Issue call before its per-call options.
func WithIssuerRuntimeOptions(options ...IssuerOption) IssuerConfigOption {
	return func(issuer *Issuer) error {
		issuer.runtimeOptions = append([]IssuerOption(nil), options...)
		return nil
	}
}

func WithSigner(signer *sig.Signer) IssuerConfigOption {
	return func(issuer *Issuer) error {
		issuer.signer = signer
		return nil
	}
}
