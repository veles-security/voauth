package tokenresponse

import (
	"errors"

	"github.com/veles-security/voauth/token"
)

// WithTokenEncoder configures the encoder used for access, refresh, and ID tokens.
func WithTokenEncoder(encoder token.AnyTokenEncoder) EncoderConfigOption {
	return func(target *Encoder) error {
		if encoder == nil {
			return errors.New("nil token encoder")
		}
		target.tokenEncoder = encoder
		return nil
	}
}
