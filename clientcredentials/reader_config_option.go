package clientcredentials

import (
	"errors"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithReaderMaxBodyBytes configures the maximum client credentials form body size.
func WithReaderMaxBodyBytes(maxBytes int64) ReaderConfigOption {
	return func(reader *Reader) error {
		if maxBytes <= 0 {
			return errors.New("maximum client credentials body size must be positive")
		}
		reader.maxBodyBytes = maxBytes
		return nil
	}
}

// WithReaderTokenDecoder configures the decoder used for client assertions.
func WithReaderTokenDecoder(decoder token.AnyTokenDecoder) ReaderConfigOption {
	return func(reader *Reader) error {
		if decoder == nil {
			return errors.New("nil token decoder")
		}
		reader.tokenDecoder = decoder
		return nil
	}
}

// WithReaderTokenDecoderOptions constructs the decoder used for client assertions
// with the provided JWT decoder configuration options.
func WithReaderTokenDecoderOptions(options ...jwt.DecoderConfigOption) ReaderConfigOption {
	return func(reader *Reader) error {
		decoder, err := jwt.NewDecoder(options...)
		if err != nil {
			return err
		}
		reader.tokenDecoder = decoder
		return nil
	}
}

// WithReaderRuntimeOptions configures reader options that are applied to every
// ReadArtifact call before its per-call options.
func WithReaderRuntimeOptions(options ...ReaderOption) ReaderConfigOption {
	return func(reader *Reader) error {
		reader.runtimeOptions = append([]ReaderOption(nil), options...)
		return nil
	}
}
