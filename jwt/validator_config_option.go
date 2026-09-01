package jwt

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/jws"
)

// WithValidatorRuntimeOptions configures validator options that are applied to
// every Validate call before its per-call options.
func WithValidatorRuntimeOptions(options ...ValidatorOption) ValidatorConfigOption {
	return func(validator *Validator) error {
		validator.runtimeOptions = append([]ValidatorOption(nil), options...)
		return nil
	}
}

// WithValidatorVerifier configures the verifier used to verify JWT signatures.
func WithValidatorVerifier(verifier vapi.Verifier[jws.VerifierOption]) ValidatorConfigOption {
	return func(validator *Validator) error {
		validator.verifier = verifier
		return nil
	}
}
