package jwks

import (
	"errors"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwk"
)

// WithJwkDecoder configures the decoder used to decode each JWK in a set.
func WithJwkDecoder(decoder vapi.Decoder[*jwk.Jwk, jwk.DecoderOption]) DecoderConfigOption {
	return func(target *Decoder) error {
		if decoder == nil {
			return errors.New("nil JWK decoder")
		}
		target.jwkDecoder = decoder
		return nil
	}
}

// WithJwkDecoderOptions configures the decoder used to decode each JWK in a
// set by constructing it with the provided JWK decoder configuration options.
func WithJwkDecoderOptions(options ...jwk.DecoderConfigOption) DecoderConfigOption {
	return func(target *Decoder) error {
		decoder, err := jwk.NewDecoder(options...)
		if err != nil {
			return err
		}
		target.jwkDecoder = decoder
		return nil
	}
}

// WithDecoderRuntimeOptions configures decoder options that are applied to
// every Decode call before its per-call options.
func WithDecoderRuntimeOptions(options ...DecoderOption) DecoderConfigOption {
	return func(decoder *Decoder) error {
		decoder.runtimeOptions = append([]DecoderOption(nil), options...)
		return nil
	}
}
