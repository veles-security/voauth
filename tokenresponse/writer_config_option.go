package tokenresponse

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithWriterEncoder configures the encoder used to encode token responses.
func WithWriterEncoder(encoder vapi.Encoder[*TokenResponse, EncoderOption]) WriterConfigOption {
	return func(target *Writer) error {
		if encoder == nil {
			return errors.New("nil token response encoder")
		}
		target.encoder = encoder
		return nil
	}
}

// WithWriterEncoderOptions constructs the encoder used to encode token responses
// with the provided configuration options.
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
