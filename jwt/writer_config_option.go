package jwt

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithWriterEncoder configures the encoder used to encode JWTs.
func WithWriterEncoder(encoder vapi.Encoder[*Token, EncoderOption]) WriterConfigOption {
	return func(writer *Writer) error {
		if encoder == nil {
			return errors.New("nil JWT encoder")
		}
		writer.encoder = encoder
		return nil
	}
}

// WithWriterEncoderOptions constructs the encoder used to encode JWTs with the
// provided encoder configuration options.
func WithWriterEncoderOptions(options ...EncoderConfigOption) WriterConfigOption {
	return func(writer *Writer) error {
		encoder, err := NewEncoder(options...)
		if err != nil {
			return err
		}
		writer.encoder = encoder
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
