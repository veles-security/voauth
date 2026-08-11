package tokenrequest

import (
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithWriterTokenEncoder configures the encoder used for refresh tokens.
func WithWriterTokenEncoder(encoder token.AnyTokenEncoder) WriterConfigOption {
	return func(writer *Writer) error {
		if encoder == nil {
			return errors.New("nil token encoder")
		}
		writer.tokenEncoder = encoder
		return nil
	}
}

// WithWriterTokenEncoderOptions constructs the encoder used for refresh tokens
// with the provided JWT encoder configuration options.
func WithWriterTokenEncoderOptions(options ...jwt.EncoderConfigOption) WriterConfigOption {
	return func(writer *Writer) error {
		encoder, err := jwt.NewEncoder(options...)
		if err != nil {
			return err
		}
		writer.tokenEncoder = encoder
		return nil
	}
}

// WithWriterAssertionTokenEncoder configures the encoder used for JWT and SAML
// bearer assertions.
func WithWriterAssertionTokenEncoder(encoder token.AnyTokenEncoder) WriterConfigOption {
	return func(writer *Writer) error {
		if encoder == nil {
			return errors.New("nil assertion token encoder")
		}
		writer.assertionTokenEncoder = encoder
		return nil
	}
}

// WithWriterAssertionTokenEncoderOptions constructs the encoder used for JWT
// and SAML bearer assertions with the provided JWT encoder configuration options.
func WithWriterAssertionTokenEncoderOptions(options ...jwt.EncoderConfigOption) WriterConfigOption {
	return func(writer *Writer) error {
		encoder, err := jwt.NewEncoder(options...)
		if err != nil {
			return err
		}
		writer.assertionTokenEncoder = encoder
		return nil
	}
}

// WithWriterClientCredentialsWriter configures the writer used for client credentials.
func WithWriterClientCredentialsWriter(writer vapi.Writer[*http.Request, *clientcredentials.ClientCredentials, clientcredentials.WriterOption]) WriterConfigOption {
	return func(tokenRequestWriter *Writer) error {
		if writer == nil {
			return errors.New("nil client credentials writer")
		}
		tokenRequestWriter.clientCredentialsWriter = writer
		return nil
	}
}

// WithWriterClientCredentialsWriterOptions constructs the writer used for
// client credentials with the provided configuration options.
func WithWriterClientCredentialsWriterOptions(options ...clientcredentials.WriterConfigOption) WriterConfigOption {
	return func(writer *Writer) error {
		clientCredentialsWriter, err := clientcredentials.NewWriter(options...)
		if err != nil {
			return err
		}
		writer.clientCredentialsWriter = clientCredentialsWriter
		return nil
	}
}

// WithWriterRuntimeOptions configures writer options that are applied to every
// WriteArtifact call before its per-call options.
func WithWriterRuntimeOptions(options ...WriterOption) WriterConfigOption {
	return func(writer *Writer) error {
		writer.runtimeOptions = append([]WriterOption(nil), options...)
		return nil
	}
}
