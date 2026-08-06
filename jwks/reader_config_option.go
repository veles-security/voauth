package jwks

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithReaderDecoder configures the decoder used to decode JWKS responses.
func WithReaderDecoder(decoder vapi.Decoder[*Jwks, DecoderOption]) ReaderConfigOption {
	return func(reader *Reader) error {
		if decoder == nil {
			return errors.New("nil JWKS decoder")
		}
		reader.decoder = decoder
		return nil
	}
}

// WithReaderDecoderOptions constructs the decoder used to decode JWKS responses
// with the provided configuration options.
func WithReaderDecoderOptions(options ...DecoderConfigOption) ReaderConfigOption {
	return func(reader *Reader) error {
		decoder, err := NewDecoder(options...)
		if err != nil {
			return err
		}
		reader.decoder = decoder
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
