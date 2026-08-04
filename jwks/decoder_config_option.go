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
