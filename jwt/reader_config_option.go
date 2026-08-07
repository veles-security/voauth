package jwt

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithReaderDecoder configures the decoder used to decode JWTs.
func WithReaderDecoder(decoder vapi.Decoder[*Token, DecoderOption]) ReaderConfigOption {
	return func(reader *Reader) error {
		if decoder == nil {
			return errors.New("nil JWT decoder")
		}
		reader.decoder = decoder
		return nil
	}
}

// WithReaderDecoderOptions constructs the decoder used to decode JWTs with the
// provided decoder configuration options.
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
