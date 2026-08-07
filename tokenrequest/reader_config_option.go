package tokenrequest

import (
	"errors"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithReaderAssertionTokenDecoder configures the decoder used for JWT and
// SAML bearer assertions.
func WithReaderAssertionTokenDecoder(decoder token.AnyTokenDecoder) ReaderConfigOption {
	return func(reader *Reader) error {
		if decoder == nil {
			return errors.New("nil assertion token decoder")
		}
		reader.assertionTokenDecoder = decoder
		return nil
	}
}

// WithReaderAssertionTokenDecoderOptions constructs the decoder used for JWT
// and SAML bearer assertions with the provided JWT decoder configuration options.
func WithReaderAssertionTokenDecoderOptions(options ...jwt.DecoderConfigOption) ReaderConfigOption {
	return func(reader *Reader) error {
		decoder, err := jwt.NewDecoder(options...)
		if err != nil {
			return err
		}
		reader.assertionTokenDecoder = decoder
		return nil
	}
}
