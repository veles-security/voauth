package clientcredentials

import (
	"errors"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithWriterTokenEncoder configures the encoder used for client assertions.
func WithWriterTokenEncoder(encoder token.AnyTokenEncoder) WriterConfigOption {
	return func(writer *Writer) error {
		if encoder == nil {
			return errors.New("nil token encoder")
		}
		writer.tokenEncoder = encoder
		return nil
	}
}

// WithWriterTokenEncoderOptions constructs the encoder used for client assertions
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

// WithWriterRuntimeOptions configures writer options that are applied to every
// WriteArtifact call before its per-call options.
func WithWriterRuntimeOptions(options ...WriterOption) WriterConfigOption {
	return func(writer *Writer) error {
		writer.runtimeOptions = append([]WriterOption(nil), options...)
		return nil
	}
}
