package tokenrequest

import (
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithReaderMaxBodyBytes configures the maximum token request form body size.
func WithReaderMaxBodyBytes(maxBytes int64) ReaderConfigOption {
	return func(reader *Reader) error {
		if maxBytes <= 0 {
			return errors.New("maximum token request body size must be positive")
		}
		reader.maxBodyBytes = maxBytes
		return nil
	}
}

// WithReaderTokenDecoder configures the decoder used for refresh tokens.
func WithReaderTokenDecoder(decoder token.AnyTokenDecoder) ReaderConfigOption {
	return func(reader *Reader) error {
		if decoder == nil {
			return errors.New("nil token decoder")
		}
		reader.tokenDecoder = decoder
		return nil
	}
}

// WithReaderTokenDecoderOptions constructs the decoder used for refresh tokens
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

// WithReaderClientCredentialsReader configures the reader used for client credentials.
func WithReaderClientCredentialsReader(reader vapi.Reader[*http.Request, *clientcredentials.ClientCredentials, clientcredentials.ReaderOption]) ReaderConfigOption {
	return func(tokenRequestReader *Reader) error {
		if reader == nil {
			return errors.New("nil client credentials reader")
		}
		tokenRequestReader.clientCredentialsReader = reader
		return nil
	}
}

// WithReaderClientCredentialsReaderOptions constructs the reader used for
// client credentials with the provided configuration options.
func WithReaderClientCredentialsReaderOptions(options ...clientcredentials.ReaderConfigOption) ReaderConfigOption {
	return func(reader *Reader) error {
		clientCredentialsReader, err := clientcredentials.NewReader(options...)
		if err != nil {
			return err
		}
		reader.clientCredentialsReader = clientCredentialsReader
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
