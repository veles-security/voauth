package jwks

import (
	"errors"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwk"
)

// WithEncoderJwkEncoder configures the decoder used to decode each JWK in a set.
func WithEncoderJwkEncoder(decoder vapi.Encoder[*jwk.Jwk, jwk.EncoderOption]) EncoderConfigOption {
	return func(target *Encoder) error {
		if decoder == nil {
			return errors.New("nil JWK decoder")
		}
		target.jwkEncoder = decoder
		return nil
	}
}

// WithEncoderJwkEncoderOptions configures the decoder used to decode each JWK in a
// set by constructing it with the provided JWK decoder configuration options.
func WithEncoderJwkEncoderOptions(options ...jwk.EncoderConfigOption) EncoderConfigOption {
	return func(target *Encoder) error {
		encoder, err := jwk.NewEncoder(options...)
		if err != nil {
			return err
		}
		target.jwkEncoder = encoder
		return nil
	}
}

// WithEncoderRuntimeOptions configures encoder options that are applied to
// every Encode call before its per-call options.
func WithEncoderRuntimeOptions(options ...EncoderOption) EncoderConfigOption {
	return func(encoder *Encoder) error {
		encoder.runtimeOptions = append([]EncoderOption(nil), options...)
		return nil
	}
}
