package tokenresponse

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithDecoder configures the decoder used to decode token responses.
func WithDecoder(decoder vapi.Decoder[*TokenResponse, DecoderOption]) ReaderConfigOption {
	return func(target *Reader) error {
		if decoder == nil {
			return errors.New("nil token response decoder")
		}
		target.decoder = decoder
		return nil
	}
}
