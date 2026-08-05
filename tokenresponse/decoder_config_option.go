package tokenresponse

import (
	"errors"

	"github.com/veles-security/voauth/token"
)

// WithTokenDecoder configures the decoder used for access, refresh, and ID tokens.
func WithTokenDecoder(decoder token.AnyTokenDecoder) DecoderConfigOption {
	return func(target *Decoder) error {
		if decoder == nil {
			return errors.New("nil token decoder")
		}
		target.tokenDecoder = decoder
		return nil
	}
}
