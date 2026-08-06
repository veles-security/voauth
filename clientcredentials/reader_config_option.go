package clientcredentials

import (
	"errors"

	"github.com/veles-security/voauth/token"
)

// WithTokenDecoder configures the decoder used for client assertions.
func WithTokenDecoder(decoder token.AnyTokenDecoder) ReaderConfigOption {
	return func(reader *Reader) error {
		if decoder == nil {
			return errors.New("nil token decoder")
		}
		reader.tokenDecoder = decoder
		return nil
	}
}
