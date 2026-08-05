package tokenresponse

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithEncoder configures the encoder used to encode token responses.
func WithEncoder(encoder vapi.Encoder[*TokenResponse, EncoderOption]) WriterConfigOption {
	return func(target *Writer) error {
		if encoder == nil {
			return errors.New("nil token response encoder")
		}
		target.encoder = encoder
		return nil
	}
}
